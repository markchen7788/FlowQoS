/**
 * @file flowQoS_conntrack.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief L4-conntrack module for flowQoS, only tracking single direction and not tracking tcp 11 states
 * @version 0.1
 * @date 2024-01-13
 *
 * @copyright Copyright (c) 2024
 *
 */
#include "flowQoS_conntrack.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <doca_log.h>
#include "flowQoS_pipe.h"
#include "flowQoS_timer.h"
#include "flowQoS_cmd.h"
#include "flowQoS_qos.h"
DOCA_LOG_REGISTER(FLOWQOS_CONNTRACK);
/*****************************Struct*********************************************/

/**
 * @brief Attribution of conntrack module
 *
 */
struct FlowQoS_CONN_ATTR
{
    flowQoS_newConn_handler newConn_handler;
    flowQoS_agingConn_handler agingConn_handler;
    struct FlowQoS_PIPE *TCP_PIPE[MAX_ETHPORTS]; ///< doca-flow pipe matching TCP connection
    struct FlowQoS_PIPE *UDP_PIPE[MAX_ETHPORTS]; ///< doca-flow pipe matching UDP connection
    struct FlowQoS_PIPE *RSS_PIPE[MAX_ETHPORTS]; ///< doca-flow pipe forward new conn to control plane
    uint64_t ActionFlags[MAX_ETHPORTS];          ///< actions should do in forwarding traffic
    uint64_t TCP_MatchFlags;                     ///< TCP conn match
    uint64_t UDP_MatchFlags;                     ///< UDP conn match
    uint64_t PORT_CT_ENABLED[MAX_ETHPORTS];      ///< ports enabling conntrack
    uint64_t CPU_HZ;                             ///< cpu frequency
    uint64_t CONN_OFFLOAD_TIME;                  ///< interval between adding flow into hashTable and offloading it
    uint64_t CONN_OFFLOAD_TIME_MIN;              ///< lower bound of dynamic time threshold
    uint64_t CONN_OFFLOAD_TIME_MAX;              ///< upper bound of dynamic time threshold
    uint64_t CONN_OFFLOAD_TIME_DELTA;            ///< runtime tuning step of time threshold
    uint64_t PACKET_THRESHOLD;                   ///< minimum packet count before considering offload
    uint64_t FILTER_WINDOW_START;                ///< start timestamp of enqueue-rate tuning window
    uint64_t FILTER_WINDOW_ENQUEUED;             ///< connections enqueued in current tuning window
    uint64_t FILTER_ENQUEUED_TOTAL;              ///< total connections accepted by ConnSched-Filter
    uint64_t FILTER_REJECTED_TOTAL;              ///< total checks rejected by ConnSched-Filter
    uint64_t MAX_OFFLOAD_SPEED;                  ///< DPU max sustainable offload rate
    uint64_t MaxEntry;                           ///< maximum connections(including TCP and UDP) stored in mempool
    uint64_t MaxOffloadedEntry;                  ///< maximum connections(including TCP and UDP) can be offloaded
    bool ENABLE_FLOWQOS;                         ///< enabling flowQoS module
} __rte_cache_aligned;

/**
 * @brief connection state
 *
 */
enum CT_STATE
{
    SW_FWD_STATE,   ///< connection is handled by software
    FLOW_QOS_STATE, ///< connection is handled by flowQoS module
    HW_FWD_STATE    ///< connection is handled by hardware
};

/**
 * @brief connection context stored in mempool and hashTable
 *
 */
struct FlowQoS_CONN_CONTEXT
{
    struct FlowQoS_ENTRY entry;  ///< flowQoS_entry
    flowQoS_timer timer;         ///< software timer
    uint64_t startTimeStmp;      ///< timestamp when new conn is added into hashTable
    uint64_t lastResetTimerStmp; ///< connection state
    uint64_t pktCount;           ///< packets observed before hardware offload
    //uint64_t flowSize;           ///< add by pinesl, the packet amount of a flow
    enum CT_STATE ct_state;
    // FlowQoS module
} __rte_cache_aligned;

/**
 * @brief hashTable per-core
 *
 */
struct ConntrackTable // Hash Table of core
{
    struct rte_mempool *pool; ///< mempool storing real connection
    struct rte_hash *table;   ///< dpdk rte_hash table
    uint64_t offloadedNum;    ///< capacity of rte_hash
    //uint64_t countPacket;     ///< add by pinesl, the sum of packets in CT
    //float HN;                 ///< add by pinesl, the zipf parameter 
    //uint64_t flowNum;         ///< add by pinesl, the flow amount in SW CT
    char name[32];            ///< conntrack table name
};

/**
 * @brief L4 port info of TCP or UDP
 *
 */
struct L4_PORT
{
    uint16_t sport;
    uint16_t dport;
};

/*****************************Define*********************************************/
RTE_DEFINE_PER_LCORE(struct ConntrackTable, _CT); ///< hashTable per-core defined by using dpdk threadLocal
#define CT RTE_PER_LCORE(_CT).table               ///< return dpdk rte_hash
#define CT_NAME RTE_PER_LCORE(_CT).name           ///< return CT name
#define CT_NUM RTE_PER_LCORE(_CT).offloadedNum    ///< return capacity of rte_hash
#define POOL RTE_PER_LCORE(_CT).pool              ///< return mempool
//#define CT_PACKET RTE_PER_LCORE(_CT).countPacket  ///< add by pinesl, the sum of packets in CT
//#define CT_HN RTE_PER_LCORE(_CT).HN               ///< add by pinesl, the zipf parameter
//#define CT_FLOW_NUM RTE_PER_LCORE(_CT).flowNum    ///< add by pinesl, the flow amount in SW CT
typedef bool IS_L4_TRAFFIC;                       ///< Is L4 traffic(TCP and UDP)
#define L4_TCP 6                                  ///< proto num of TCP
#define L4_UDP 17                                 ///< proto num of UDP
#define MAX_CT_STATS 50                           ///< maximum conntrack info per-core can be printed onto cmdline
#define CONNSCHED_DEFAULT_PACKET_THRESHOLD 136    ///< Pth from ConnSched evaluation
#define CONNSCHED_DEFAULT_DELTA_TIME_US 1000      ///< delta_t from ConnSched evaluation
#define CONNSCHED_TUNING_WINDOW_US 1000000        ///< enqueue-rate tuning window
#define CONNSCHED_DEFAULT_MAX_TTH_SEC 10          ///< default upper bound matches default SW aging timeout
/*****************************Static data*****************************************/

/**
 * @brief struct storing detailed conntrack info
 *
 */
struct ConntrackStats
{
    uint64_t count;                           ///< count of connection currently
    struct FlowQoS_ENTRY entry[MAX_CT_STATS]; ///< detailed conntrack info
} ctStats[MAX_CORES] = {0};

/**
 * @brief init attributes of conntrack module
 *
 */
static struct FlowQoS_CONN_ATTR attr = {
    .newConn_handler = NULL,
    .agingConn_handler = NULL,
    .TCP_PIPE = {NULL},
    .UDP_PIPE = {NULL},
    .RSS_PIPE = {NULL},
    .ActionFlags = {0},
    .TCP_MatchFlags = SIP | DIP | TCP | SPORT | DPORT,
    .UDP_MatchFlags = SIP | DIP | UDP | SPORT | DPORT,
    .PORT_CT_ENABLED = {0},
    .CPU_HZ = 0,
    .CONN_OFFLOAD_TIME = 0,
    .CONN_OFFLOAD_TIME_MIN = 0,
    .CONN_OFFLOAD_TIME_MAX = 0,
    .CONN_OFFLOAD_TIME_DELTA = 0,
    .PACKET_THRESHOLD = 0,
    .FILTER_WINDOW_START = 0,
    .FILTER_WINDOW_ENQUEUED = 0,
    .FILTER_ENQUEUED_TOTAL = 0,
    .FILTER_REJECTED_TOTAL = 0,
    .MAX_OFFLOAD_SPEED = 0};

/*****************************Function*****************************************/

/**
 * @brief software timer callback defined in flowQoS timer
 * 
 * @param timer 
 */
void flowQoS_conn_expire_sw_cb(flowQoS_timer *timer);
/**
 * @brief hardware timer callback defined in doca-flow 
 * 
 * @param args 
 */
void flowQoS_conn_expire_hw_cb(void *args);
/**
 * @brief register cmds from conntrack module into dpdk cmdline
 * 
 */
void registerConntrackCmd();
/**
 * @brief make ConnSched-Filter more selective when QoS detects hardware pressure
 *
 * @param occupied
 * @param maxEntry
 * @param args
 */
void flowQoS_filter_congestion_cb(uint64_t occupied, uint64_t maxEntry, void *args);

/**
 * @brief user-defined hash fun revoked by rte_hash, which uses rss val directly as the result. 
 * 
 * @param key 
 * @param key_len 
 * @param init_val 
 * @return uint32_t 
 */
uint32_t myHash(const void *key, uint32_t key_len, uint32_t init_val)
{
    struct FlowQoS_MATCH *mt = (struct FlowQoS_MATCH *)key;
    // DOCA_LOG_INFO("RSS:%u", mt->rss);
    return mt->rss; // rss val is precomputed hash val by hw
}

/**
 * @brief init conntrack table per-core
 * 
 * @param dummy 
 * @return int 
 */
int flowQoS_init_per_core(__rte_unused void *dummy)
{
    uint64_t *args = (uint64_t *)dummy;
    uint64_t MAX_CT = args[0];
    POOL = (struct rte_mempool *)(args[1]);

    if (POOL == NULL)
    {
        DOCA_LOG_ERR("Add pool to this core fail, Pool is NULL.....");
    }
    DOCA_LOG_INFO("Add pool to this core success.....");

    int cid = rte_lcore_id();
    sprintf(CT_NAME, "CT-%d", cid);
    const struct rte_hash_parameters ConnectionTable =
        {
            .name = CT_NAME,
            .entries = MAX_CT,
            .reserved = 0,
            .key_len = sizeof(struct FlowQoS_MATCH),
            .hash_func = myHash, // rte_jhash,
            .hash_func_init_val = 0,
            .socket_id = rte_socket_id(),
            .extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE, // 0,
        };

    CT = rte_hash_create(&ConnectionTable);
    if (!CT)
    {
        ((int *)dummy)[2] = 1;
        DOCA_LOG_ERR("Core %d Create ConnectionTable fail!", cid);
        return -1;
    }
    DOCA_LOG_INFO("Core %d Create %s[%lu] success", cid, CT_NAME, MAX_CT);

    CT_NUM = attr.MaxOffloadedEntry;

    args[2]++;//this is the flag of success
    return 0;
}

/**
 * @brief get the conn_context from pool and memcpy info from newEntry 
 * 
 * @param newEntry defined new entry
 * @return struct FlowQoS_CONN_CONTEXT* the pointer of conn_context
 */
struct FlowQoS_CONN_CONTEXT *flowQoS_addConnToHash(struct FlowQoS_ENTRY *newEntry)
{
    ///////////////////////////////////////////////////////////// 1.get a ctx from pool
    struct FlowQoS_CONN_CONTEXT *ctx = NULL;
    if (POOL == NULL)
    {
        DOCA_LOG_ERR("Pool is NULL.....");
        return NULL;
    }
    if (rte_mempool_get(POOL, (void **)&ctx) != 0)
    {
        DOCA_LOG_ERR("Cannot get ctx from pool.....");
        return NULL;
    }
    // DOCA_LOG_INFO("CTX_POOL In Use:%d", rte_mempool_in_use_count(POOL));

    ///////////////////////////////////////////////////////////// 2.put match->ctx into CT
    int ret = rte_hash_add_key_data(CT, &(newEntry->match), ctx);
    if (ret < 0)
    {
        if (ret == -EINVAL)
        {
            DOCA_LOG_ERR("Invalid params.....");
        }
        else
            DOCA_LOG_ERR("No space.....");

        rte_mempool_put(POOL, (void *)ctx);
        return NULL;
    }

    ///////////////////////////////////////////////////////////// 3.memcpy info
    rte_memcpy(&(ctx->entry), newEntry, sizeof(struct FlowQoS_ENTRY));
    // DOCA_LOG_INFO("%s Count:%d", CT_NAME, rte_hash_count(CT));

    ///////////////////////////////////////////////////////////// 4.attach Timer
    if (ctx->entry.action.flags ^ AGING)
    {
        if (ctx->entry.expireTime == 0)
            ctx->entry.expireTime = 10;

        flowQoS_timer_add(&(ctx->timer), flowQoS_conn_expire_sw_cb, (void *)ctx, ctx->entry.expireTime * 1000);
        ctx->startTimeStmp = rte_rdtsc();
        // DOCA_LOG_INFO("Attach SW Timer");

        // attch hw timer
        ctx->entry.cb = flowQoS_conn_expire_hw_cb;
        ctx->entry.cb_args = (void *)ctx;
    }

    ////////////////////////////////////////////////////////////5.change ct_state
    ctx->pktCount = 0;
    ctx->ct_state = SW_FWD_STATE;

    return ctx;
}

/**
 * @brief find the conn_context from rte_hash
 * 
 * @param newEntry 
 * @return struct FlowQoS_CONN_CONTEXT* 
 */
struct FlowQoS_CONN_CONTEXT *flowQoS_findConnFromHash(struct FlowQoS_ENTRY *newEntry)
{
    struct FlowQoS_CONN_CONTEXT *ctx = NULL;
    int ret = rte_hash_lookup_data(CT, &(newEntry->match), (void **)&ctx);
    return ret >= 0 ? ctx : NULL;
}
/**
 * @brief del the conn_context from rte_hash and put it back to mempool
 * 
 * @param ctx 
 * @return int 
 */
int flowQoS_delConnFromHash(struct FlowQoS_CONN_CONTEXT *ctx)
{

    int ret = rte_hash_del_key(CT, &(ctx->entry.match));
    if (ret >= 0)
    {
	//CT_PACKET -= ctx->flowSize; //add by pinesl
        // DOCA_LOG_INFO("Del Success");
    }
    else if (ret == -ENOENT)
    {
        DOCA_LOG_ERR("Not Found");
    }
    else
        DOCA_LOG_ERR("Invalid");

    // DOCA_LOG_INFO("%s Count:%d", CT_NAME, rte_hash_count(CT));

    rte_mempool_put(POOL, (void *)ctx);
    // DOCA_LOG_INFO("CTX_POOL Avail:%d", rte_mempool_avail_count(POOL));
    return 0;
}

void flowQoS_conn_expire_sw_cb(flowQoS_timer *timer)
{
    struct FlowQoS_CONN_CONTEXT *ctx = (struct FlowQoS_CONN_CONTEXT *)(timer->cb_args);
    flowQoS_delConnFromHash(ctx);
    double gap = rte_rdtsc() - ctx->startTimeStmp, unit = attr.CPU_HZ;
    gap = gap / unit;

    if (attr.ENABLE_FLOWQOS && ctx->ct_state == FLOW_QOS_STATE)
    {
        flowQoS_del_entry_event(&(ctx->entry));
        // DOCA_LOG_INFO("Aging From SW:Total Duration %.2f==>flowQoS_del_entry_event", gap);
    }
    if (attr.agingConn_handler)
        attr.agingConn_handler(&(ctx->entry));
    // DOCA_LOG_INFO("Aging From SW:Total Duration %.2f", gap);
}

void flowQoS_conn_expire_hw_cb(void *args)
{
    struct FlowQoS_CONN_CONTEXT *ctx = (struct FlowQoS_CONN_CONTEXT *)(args);
    flowQoS_delConnFromHash(ctx);
    double gap = rte_rdtsc() - ctx->startTimeStmp, unit = attr.CPU_HZ;
    gap = gap / unit;

    if (attr.ENABLE_FLOWQOS && ctx->ct_state == HW_FWD_STATE)
    {
        flowQoS_return_entry_event();
        // DOCA_LOG_INFO("Aging From HW:Total Duration %.2f==>flowQoS_return_entry_event", gap);
    }
    else
    {
        CT_NUM++;
    }
    if (attr.agingConn_handler)
        attr.agingConn_handler(&(ctx->entry));
    // DOCA_LOG_INFO("Aging From HW:Total Duration %.2f", gap);
}

/**
 * @brief the general processor of polling aged conn from doca-flow, it will revoke the pre-defined hardware callback
 * 
 * @param cid 
 * @return int the num of aged conn 
 */
int flowQoS_conn_aging_handle(int cid)
{
    int ret = 0;
    for (int i = 0; i < MAX_ETHPORTS; i++)
    {
        if (attr.PORT_CT_ENABLED[i])
        {
            ret += flowQoS_aging_handle(i, getFlowQid(cid));
        }
    }
    return ret;
}

/**
 * @brief if the conn has established for enough time(the interval is defined in flowQoS_conntrack_init_env()) and not been offloaded.
 * 
 * @param ctx 
 * @return true 
 * @return false 
 */
bool flowQoS_should_offload_ct(struct FlowQoS_CONN_CONTEXT *ctx)
{
//    CT_PACKET++;
//    ctx->flowSize++;
//    if(ctx->flowSize == 1)
//    {
//	CT_FLOW_NUM++;
//	CT_HN = CT_HN + 1/CT_FLOW_NUM;
//    }
    //if(CT_FLOW_NUM <= CT_NUM)  {return ctx->ct_state == SW_FWD_STATE;}
    //float topK = CT_PACKET * (1.0 / CT_HN / CT_NUM);
    //return (ctx->ct_state == SW_FWD_STATE) && (ctx->flowSize >= topK);
    //return (ctx->ct_state == SW_FWD_STATE) && (ctx->flowSize >= CT_PACKET / CT_FLOW_NUM); // add by pinesl
    uint64_t gap = rte_rdtsc() - ctx->startTimeStmp;
    bool ready = (ctx->ct_state == SW_FWD_STATE) &&
                 (gap > attr.CONN_OFFLOAD_TIME) &&
                 (ctx->pktCount > attr.PACKET_THRESHOLD);
    if (!ready && ctx->ct_state == SW_FWD_STATE)
    {
        attr.FILTER_REJECTED_TOTAL++;
    }
    return ready; // After offload this flow, you have to handle left onloaded pkts
}

void flowQoS_filter_runtime_tune()
{
    if (!attr.ENABLE_FLOWQOS || attr.MAX_OFFLOAD_SPEED == 0)
        return;

    uint64_t now = rte_rdtsc();
    uint64_t window = attr.CPU_HZ * CONNSCHED_TUNING_WINDOW_US / 1000000;
    if (attr.FILTER_WINDOW_START == 0)
    {
        attr.FILTER_WINDOW_START = now;
        return;
    }
    if (now - attr.FILTER_WINDOW_START < window)
        return;

    uint64_t elapsed = now - attr.FILTER_WINDOW_START;
    uint64_t enqueueRate = attr.FILTER_WINDOW_ENQUEUED * attr.CPU_HZ / elapsed;
    if (enqueueRate > attr.MAX_OFFLOAD_SPEED)
    {
        attr.CONN_OFFLOAD_TIME += attr.CONN_OFFLOAD_TIME_DELTA;
        if (attr.CONN_OFFLOAD_TIME > attr.CONN_OFFLOAD_TIME_MAX)
            attr.CONN_OFFLOAD_TIME = attr.CONN_OFFLOAD_TIME_MAX;
    }
    else
    {
        if (attr.CONN_OFFLOAD_TIME > attr.CONN_OFFLOAD_TIME_MIN + attr.CONN_OFFLOAD_TIME_DELTA)
            attr.CONN_OFFLOAD_TIME -= attr.CONN_OFFLOAD_TIME_DELTA;
        else
            attr.CONN_OFFLOAD_TIME = attr.CONN_OFFLOAD_TIME_MIN;
    }

    attr.FILTER_WINDOW_ENQUEUED = 0;
    attr.FILTER_WINDOW_START = now;
}

void flowQoS_filter_congestion_cb(__rte_unused uint64_t occupied, __rte_unused uint64_t maxEntry, __rte_unused void *args)
{
    if (!attr.ENABLE_FLOWQOS)
        return;

    attr.CONN_OFFLOAD_TIME *= 2;
    if (attr.CONN_OFFLOAD_TIME > attr.CONN_OFFLOAD_TIME_MAX)
        attr.CONN_OFFLOAD_TIME = attr.CONN_OFFLOAD_TIME_MAX;
}

/**
 * @brief the callback revoked when flowQoS module offloading the conn, including changing the conn state and deleting the software timer 
 * 
 * @param args 
 */
void flowQoS_qosHandler(void *args)
{
    struct FlowQoS_CONN_CONTEXT *ctx = (struct FlowQoS_CONN_CONTEXT *)args;
    if (ctx->entry.action.flags ^ AGING)
    {
        flowQoS_timer_del(&(ctx->timer));
        // DOCA_LOG_INFO("FlowQoS:Remove sw timer and attach hw timer");
    }
    ctx->ct_state = HW_FWD_STATE;
    // DOCA_LOG_INFO("FlowQoS:HW offload");
}

/**
 * @brief the func of offloading conn, which will be revoked when l4-packet received
 * 
 * @param ctx 
 * @return int 
 */
int flowQoS_offload_conn(struct FlowQoS_CONN_CONTEXT *ctx)
{
    int ret = 0;
    flowQoS_filter_runtime_tune();
    if (flowQoS_should_offload_ct(ctx))//if it's time to offload
    {
        if (attr.ENABLE_FLOWQOS) //if enable flowQoS, then hand it to flowQoS module. FlowQoS module will offload it according to wrr algorithm. 
        {
            ctx->entry.flowQoS_qosHandler = flowQoS_qosHandler;
            ctx->entry.flowQoS_args = (void *)ctx;
            flowQoS_add_entry_event(&(ctx->entry), ctx->entry.priority % 4);
            ctx->ct_state = FLOW_QOS_STATE;
            attr.FILTER_WINDOW_ENQUEUED++;
            attr.FILTER_ENQUEUED_TOTAL++;
            // DOCA_LOG_INFO("FlowQoS Add Entry");
        }
        else
        {
            if (CT_NUM <= 0)// if no more doca-flow entry can be offloaded 
            {
                return 0;
            }
            ret = flowQoS_add_entry(ctx->entry.pipe, &(ctx->entry), getFlowQid(rte_lcore_id()), 1);
            if (ret)
            {
                // DOCA_LOG_INFO("Offload this Conn Success");
                if (ctx->entry.action.flags ^ AGING)
                {
                    flowQoS_timer_del(&(ctx->timer));
                    // DOCA_LOG_INFO("Remove sw timer and attach hw timer");
                }
                ctx->ct_state = HW_FWD_STATE;
		//CT_PACKET = CT_PACKET - ctx->flowSize; // add by pinesl
		//CT_FLOW_NUM--;                        // add by pinesl
                CT_NUM--;
                return 1;
            }
            else
                DOCA_LOG_ERR("Offload this Conn fail");
        }
    }
    return ret;
}

/**
 * @brief parse the l4-packet and mempcy info to newEntry
 * 
 * @param m 
 * @param newEntry 
 * @return IS_L4_TRAFFIC if it's TCP or UDP packet
 */
IS_L4_TRAFFIC flowQoS_packet_parser(struct rte_mbuf *m, struct FlowQoS_ENTRY *newEntry)
{
    if (RTE_ETH_IS_IPV4_HDR(m->packet_type))
    {
        struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
        int port_id = m->port;
        newEntry->match.src_ip = ip->src_addr;
        newEntry->match.dst_ip = ip->dst_addr;
        newEntry->match.proto = ip->next_proto_id;
        newEntry->priority = ip->type_of_service;
        newEntry->action.flags = attr.ActionFlags[port_id];
        newEntry->match.rss = m->hash.rss;
        struct rte_tcp_hdr *tcp;
        struct rte_udp_hdr *udp;
        switch (ip->next_proto_id)
        {
        case L4_TCP:
            tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
            newEntry->match.src_port = tcp->src_port;
            newEntry->match.dst_port = tcp->dst_port;
            newEntry->match.flags = attr.TCP_MatchFlags;
            newEntry->pipe = attr.TCP_PIPE[port_id];
            return true;
        case L4_UDP:
            udp = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
            newEntry->match.src_port = udp->src_port;
            newEntry->match.dst_port = udp->dst_port;
            newEntry->match.flags = attr.UDP_MatchFlags;
            newEntry->pipe = attr.UDP_PIPE[port_id];
            return true;
        default:
            return false;
        }
    }
    return false;
}

/**
 * @brief modify packet's header and flush software timer according to the action in flowQoS_ENTRY
 * 
 * @param m 
 * @param ctx 
 */
void flowQoS_packet_modifyer(struct rte_mbuf *m, struct FlowQoS_CONN_CONTEXT *ctx)
{
    struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod_offset(m, struct rte_ether_hdr *, 0);
    struct L4_PORT *l4_port = rte_pktmbuf_mtod_offset(m, struct L4_PORT *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_port;
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_port;
    bool ip_cksum = false, l4_cksum = false;

    struct FlowQoS_ACTION *flowQoS_action = &(ctx->entry.action);

    if (flowQoS_action->flags & SMAC)
    {
        rte_memcpy(eth->s_addr.addr_bytes, flowQoS_action->src_mac, DOCA_ETHER_ADDR_LEN);
    }
    if (flowQoS_action->flags & DMAC)
    {
        rte_memcpy(eth->d_addr.addr_bytes, flowQoS_action->dst_mac, DOCA_ETHER_ADDR_LEN);
    }

    if (flowQoS_action->flags & SIP)
    {
        ip->src_addr = flowQoS_action->src_ip;
        ip_cksum = true;
    }
    if (flowQoS_action->flags & DIP)
    {
        ip->dst_addr = flowQoS_action->dst_ip;
        ip_cksum = true;
    }
    if (flowQoS_action->flags & TTL_DECREASE)
    {
        ip->time_to_live--;
        ip_cksum = true;
    }
    if (flowQoS_action->flags & SPORT)
    {
        l4_port->sport = flowQoS_action->src_port;
        l4_cksum = true;
    }
    if (flowQoS_action->flags & DPORT)
    {
        l4_port->dport = flowQoS_action->dst_port;
        l4_cksum = true;
    }

    if (flowQoS_action->flags & AGING)
    {
        if (rte_rdtsc() - ctx->lastResetTimerStmp > attr.CPU_HZ && ctx->ct_state != HW_FWD_STATE) // Flush Timer almost every 1 sec, if conn offloaded then don't need flush timer
        {
            // DOCA_LOG_INFO("FlushTimer");
            ctx->lastResetTimerStmp = rte_rdtsc();
            flowQoS_timer_reset(&(ctx->timer), ctx->entry.expireTime * 1000);
        }
    }

    if (ip_cksum)
    {
        ip->hdr_checksum = 0;
        m->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
    }
    if (l4_cksum)
    {
        if (ctx->entry.match.proto == L4_TCP)
        {
            tcp->cksum = 0;
            m->ol_flags |= PKT_TX_TCP_CKSUM;
        }
        if (ctx->entry.match.proto == L4_UDP)
        {
            udp->dgram_cksum = 0;
            m->ol_flags |= PKT_TX_UDP_CKSUM;
        }
    }
}

/**
 * @brief packet processor registered in flowQoS_worker module
 * 
 * @param m 
 * @return packet_action 
 */
packet_action flowQoS_conntrack_packet_processor(struct rte_mbuf *m)
{
    struct FlowQoS_ENTRY newEntry = {0};
    struct FlowQoS_CONN_CONTEXT *ctx = NULL;
    rte_prefetch0(rte_pktmbuf_mtod(m, void *));
    if (attr.PORT_CT_ENABLED[m->port])
    {
        IS_L4_TRAFFIC isL4 = flowQoS_packet_parser(m, &newEntry);
        if (isL4)
        {
            ctx = flowQoS_findConnFromHash(&newEntry);
            if (!ctx)
            {
                if (likely(attr.newConn_handler))
                {
                    packet_action port = attr.newConn_handler(&newEntry);
                    if (port < 0)
                    {
                        newEntry.pipe = NULL; // DROP packets from this flow
                        return DROP_PACKETS;
                    }
                    ctx = flowQoS_addConnToHash(&newEntry);
                    if (!ctx)
                        return DROP_PACKETS;
                }
                else
                    return DROP_PACKETS;
            }
            ctx->pktCount++;

            // offload this conn immediately
            flowQoS_offload_conn(ctx);

            packet_action port = ctx->entry.pipe->port_id;
            flowQoS_packet_modifyer(m, ctx);
            return port ^ 1;
        }
    }
    return IGNORE_PACKETS;
}

int flowQoS_regist_newConn_handler(flowQoS_newConn_handler _newConn_handler)
{

    attr.newConn_handler = _newConn_handler;
    return 1;
}

int flowQoS_regist_agingConn_handler(flowQoS_agingConn_handler _agingConn_handler)
{

    attr.agingConn_handler = _agingConn_handler;
    return 1;
}

int flowQoS_conntrack_init_env(int maxConntrack, int maxOffloadedEntry, int offloadTime /*us*/, int offloadSpeed)
{
    uint64_t args[3] = {maxConntrack * 1.2 / (rte_lcore_count() - 1), 0, 0};
    unsigned lcore_id;
    POOL = rte_mempool_create("CT_CTX_POOL", maxConntrack,
                              sizeof(struct FlowQoS_CONN_CONTEXT), maxConntrack / 4 > 256 ? 256 : maxConntrack / 4, 0,
                              NULL, NULL, NULL, NULL,
                              rte_socket_id(), 0);
    args[1] = (uint64_t)POOL;
    if (!POOL)
    {
        DOCA_LOG_ERR("Create CT_CTX_POOL fail!");
        return 0;
    }
    DOCA_LOG_INFO("Create CT_CTX_POOL success");

    attr.CPU_HZ = rte_get_tsc_hz();
    attr.CONN_OFFLOAD_TIME = offloadTime * (rte_get_tsc_hz() / 1000000);
    attr.CONN_OFFLOAD_TIME_MIN = attr.CONN_OFFLOAD_TIME;
    attr.CONN_OFFLOAD_TIME_MAX = CONNSCHED_DEFAULT_MAX_TTH_SEC * rte_get_tsc_hz();
    if (attr.CONN_OFFLOAD_TIME_MAX < attr.CONN_OFFLOAD_TIME_MIN)
        attr.CONN_OFFLOAD_TIME_MAX = attr.CONN_OFFLOAD_TIME_MIN;
    attr.CONN_OFFLOAD_TIME_DELTA = CONNSCHED_DEFAULT_DELTA_TIME_US * (rte_get_tsc_hz() / 1000000);
    attr.PACKET_THRESHOLD = offloadSpeed > 0 ? CONNSCHED_DEFAULT_PACKET_THRESHOLD : 0;
    attr.FILTER_WINDOW_START = rte_rdtsc();
    attr.FILTER_WINDOW_ENQUEUED = 0;
    attr.FILTER_ENQUEUED_TOTAL = 0;
    attr.FILTER_REJECTED_TOTAL = 0;
    attr.MAX_OFFLOAD_SPEED = offloadSpeed;
    attr.MaxEntry = maxConntrack;
    attr.MaxOffloadedEntry = maxOffloadedEntry;
    if (offloadSpeed > 0)
    {
        attr.ENABLE_FLOWQOS = true;
        int weight[4] = {1, 1, 2, 4};
        flowQoS_qos_init(4, weight, maxOffloadedEntry, offloadSpeed);
        flowQoS_regist_congestion_handler(flowQoS_filter_congestion_cb, NULL);
        DOCA_LOG_INFO("Enable FlowQoS Already");
    }
    else
        attr.ENABLE_FLOWQOS = false;

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        rte_eal_remote_launch(flowQoS_init_per_core, (void *)args, lcore_id);
        rte_eal_wait_lcore(lcore_id);
    }
    if (args[2] != rte_lcore_count() - 1)
    {
        DOCA_LOG_ERR("Create rte_hash fail!");
        return 0;
    }
    registerConntrackCmd();
    flowQoS_timer_init();
    register_packet_processor(flowQoS_conntrack_packet_processor);
    register_general_processor(flowQoS_conn_aging_handle, "Aging");
    DOCA_LOG_INFO("register flowQoS_conntrack_packet_processor");
    return 1;
}

int flowQoS_conntrack_tune_filter(int timeThresholdUs, int packetThreshold, int deltaTimeUs, int maxOffloadSpeed)
{
    if (attr.CPU_HZ == 0)
        return 0;

    if (timeThresholdUs >= 0)
    {
        attr.CONN_OFFLOAD_TIME = (uint64_t)timeThresholdUs * (attr.CPU_HZ / 1000000);
        attr.CONN_OFFLOAD_TIME_MIN = attr.CONN_OFFLOAD_TIME;
    }
    if (packetThreshold >= 0)
    {
        attr.PACKET_THRESHOLD = packetThreshold;
    }
    if (deltaTimeUs >= 0)
    {
        attr.CONN_OFFLOAD_TIME_DELTA = (uint64_t)deltaTimeUs * (attr.CPU_HZ / 1000000);
    }
    if (maxOffloadSpeed >= 0)
    {
        attr.MAX_OFFLOAD_SPEED = maxOffloadSpeed;
    }

    if (attr.CONN_OFFLOAD_TIME > attr.CONN_OFFLOAD_TIME_MAX)
        attr.CONN_OFFLOAD_TIME = attr.CONN_OFFLOAD_TIME_MAX;
    if (attr.CONN_OFFLOAD_TIME_MIN > attr.CONN_OFFLOAD_TIME_MAX)
        attr.CONN_OFFLOAD_TIME_MIN = attr.CONN_OFFLOAD_TIME_MAX;

    return 1;
}

int flowQoS_conntrack_init_port(int port_id, int maxOffloadedEntry, uint64_t actionFlags)
{
    attr.ActionFlags[port_id] = actionFlags;
    struct FlowQoS_ENTRY rssEntry;
    memset(&rssEntry, 0, sizeof(rssEntry));
    int port = port_id;
    char name[30];
    sprintf(name, "RSS-PIPE-Port%d", port);
    attr.RSS_PIPE[port] = flowQoS_build_pipe(port, name, 0, 0, RSS_TO_QUEUE, DROP, !IS_ROOT, 2);
    int ret = flowQoS_add_entry(attr.RSS_PIPE[port], &(rssEntry), 0, 1);
    if (attr.RSS_PIPE[port] == NULL || ret < 0)
    {
        DOCA_LOG_ERR("Port %d Create attr.RSS_PIPE ERR", port);
        return 0;
    }
    sprintf(name, "UDP-PIPE-Port%d", port);
    attr.UDP_PIPE[port] = flowQoS_build_pipe(port, name, attr.UDP_MatchFlags | UDP, attr.ActionFlags[port], PORT, (FlowQoS_FWD)(attr.RSS_PIPE[port]), IS_ROOT, maxOffloadedEntry + 1); // UDP max entry(2048) is not accurate as real capacity(1260) of UDP PIPE
    if (attr.UDP_PIPE[port] == NULL)
    {
        DOCA_LOG_ERR("Port %d Create attr.UDP_PIPE ERR", port);
        return 0;
    }

    sprintf(name, "TCP-PIPE-Port%d", port);
    attr.TCP_PIPE[port] = flowQoS_build_pipe(port, name, attr.TCP_MatchFlags, attr.ActionFlags[port], PORT, (FlowQoS_FWD)(attr.RSS_PIPE[port]), IS_ROOT, maxOffloadedEntry + 1);
    if (attr.TCP_PIPE[port] == NULL)
    {
        DOCA_LOG_ERR("Port %d Create attr.TCP_PIPE ERR", port);
        return 0;
    }

    attr.PORT_CT_ENABLED[port_id] = 1;
    DOCA_LOG_INFO("Port %d Enable Conntrack", port_id);
    return 1;
}

/**
 * @brief conntrack cmd slave running in slave cores, which will get the amount of conn in rte_hash per-core
 * 
 * @param args 
 */
void conntrack_slave(void *args)
{
    int cid = rte_lcore_id();
    ctStats[cid].count = rte_hash_count(CT);
}
/**
 * @brief conntrack cmd master running in master core, which will print the amount of conn in rte_hash per-core
 * 
 * @param cl 
 */
void conntrack_master(struct cmdline *cl)
{

    unsigned int lcore_id;
    flowQoS_message_multiThread_do(conntrack_slave, NULL);
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        cmdline_printf(cl, "Core[%d] CT-Count:%lu\n", lcore_id, ctStats[lcore_id].count);
    }
}
/**
 * @brief conntrackL cmd slave running in slave cores, which will get the detailed info of conn in rte_hash per-core
 * 
 * @param args 
 */
void conntrackL_slave(void *args)
{
    int cid = rte_lcore_id();
    struct FlowQoS_MATCH *match;
    struct FlowQoS_CONN_CONTEXT *ctx;
    uint32_t iter = 0;
    int id = 0;
    ctStats[cid].count = rte_hash_count(CT);
    while (1)
    {
        /* code */
        int ret = rte_hash_iterate(CT, (const void **)&match, (void **)&ctx, (uint32_t *)&iter);
        if (ret < 0)
            break;
        // DOCA_LOG_INFO("flags:%lu",match->flags);
        memset(&(ctStats[cid].entry[id]), 0, sizeof(struct FlowQoS_ENTRY));

        rte_memcpy(&(ctStats[cid].entry[id]), &(ctx->entry), sizeof(struct FlowQoS_ENTRY));
        id++;
        if (id == MAX_CT_STATS)
            break;
    }
}
/**
 * @brief conntrackL cmd slave running in slave cores, which will print the detailed info of conn in rte_hash per-core.
 * 
 * @param cl 
 */
void conntrackL_master(struct cmdline *cl)
{

    unsigned int lcore_id;
    flowQoS_message_multiThread_do(conntrackL_slave, NULL);
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        cmdline_printf(cl, "Core[%d] CT-Count:%lu\n", lcore_id, ctStats[lcore_id].count);
        for (int id = 0; id < ctStats[lcore_id].count && id < MAX_CT_STATS; id++)
        {
            struct EntryInfo info;
            dumpFlowQoSEntry(&(ctStats[lcore_id].entry[id]), &info);
            cmdline_printf(cl, "Core[%u]-ID[%d]:\n", lcore_id, id);
            printFlowQoSEntryToCmdline(&info);
        }
    }
}

void connSched_master(struct cmdline *cl)
{
    double tthUs = (double)attr.CONN_OFFLOAD_TIME * 1000000.0 / (double)attr.CPU_HZ;
    double minUs = (double)attr.CONN_OFFLOAD_TIME_MIN * 1000000.0 / (double)attr.CPU_HZ;
    double maxUs = (double)attr.CONN_OFFLOAD_TIME_MAX * 1000000.0 / (double)attr.CPU_HZ;
    double deltaUs = (double)attr.CONN_OFFLOAD_TIME_DELTA * 1000000.0 / (double)attr.CPU_HZ;

    cmdline_printf(cl, "******************************ConnSched Filter******************************\n");
    cmdline_printf(cl, "FlowQoS:%s V:%lu conn/s Tth:%.2fus [min %.2fus, max %.2fus] delta:%.2fus Pth:%lu\n",
                   attr.ENABLE_FLOWQOS ? "on" : "off",
                   attr.MAX_OFFLOAD_SPEED,
                   tthUs,
                   minUs,
                   maxUs,
                   deltaUs,
                   attr.PACKET_THRESHOLD);
    cmdline_printf(cl, "WindowEnqueued:%lu TotalEnqueued:%lu TotalRejected:%lu\n",
                   attr.FILTER_WINDOW_ENQUEUED,
                   attr.FILTER_ENQUEUED_TOTAL,
                   attr.FILTER_REJECTED_TOTAL);
    cmdline_printf(cl, "***************************************************************************\n");
}

/**********************************************************/

/**
 * @brief cmds in conntrack module
 * 
 */
struct cmd_dumpConntrack
{
    cmdline_fixed_string_t cmd;
};
/**
 * @brief cmd processor in conntrack module
 * 
 */
static void cmd_dumpConntrack_parsed(__rte_unused void *parsed_result,
                                     struct cmdline *cl,
                                     __rte_unused void *data)
{
    struct cmd_dumpConntrack *res = parsed_result;
    if (strcmp(res->cmd, "dumpCTPool") == 0)
    {
        rte_mempool_dump(stdout, POOL);
        cmdline_printf(cl, "POOL Avail:%u, Used:%u\n", rte_mempool_avail_count(POOL), rte_mempool_in_use_count(POOL));
    }
    if (strcmp(res->cmd, "conntrack") == 0)
    {
        conntrack_master(cl);
    }
    if (strcmp(res->cmd, "conntrackL") == 0)
    {
        conntrackL_master(cl);
    }
    if (strcmp(res->cmd, "connSched") == 0)
    {
        connSched_master(cl);
    }
}

cmdline_parse_token_string_t cmd_dumpConntrack_cmd =
    TOKEN_STRING_INITIALIZER(struct cmd_dumpConntrack, cmd, "dumpCTPool#conntrack#conntrackL#connSched");

cmdline_parse_inst_t cmd_dumpConntrack_obj = {
    .f = cmd_dumpConntrack_parsed, /* function to call */
    .data = NULL,                  /* 2nd arg of func */
    .help_str = "Output info of rte_mempool storing conn or amount of conns in rte_hash",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&cmd_dumpConntrack_cmd,
        NULL,
    },
};

void registerConntrackCmd()
{
    static bool cmdRegistered = false;
    if (!cmdRegistered)
    {
        flowQoS_registCmd(&cmd_dumpConntrack_obj);
        cmdRegistered = true;
        DOCA_LOG_INFO("Register dumpConntrack cmd");
    }
}
