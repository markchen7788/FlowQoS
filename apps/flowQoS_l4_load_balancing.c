/**
 * @file flowQoS_l4_load_balancing.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief l4 load balancing based on flowQoS
 * @version 0.1
 * @date 2024-01-23
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <stdio.h>
#include <rte_random.h>
#include "flowQoS_env.h"
#include "flowQoS_pipe.h"
#include "flowQoS_cmd.h"
#include "flowQoS_router.h"
#include "flowQoS_conntrack.h"
#include "flowQoS_qos.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
DOCA_LOG_REGISTER(FLOWQOS_L4_LOAD_BALANCING);

#define MAX_RIP_PER_VIP 8                 ///< maximum amount of real servers per virtual server
#define MAX_SERVICE 8                     ///< maximum amount of virtual servers
#define FLOWQOS_DELAY 0                   ///< interval between receiving first packet and offloading this conn
#define FLOWQOS_OFFLOAD_SPEED 100000      ///< speed of flowQoS offloading conns, 0 means disabling flowQoS
#define CONN_EXPIRE 3                     ///< expire time of conn
#define LB_MAX_CT 1 << 22                 ///< maximum amount of conns in mempool, CPS-Test: 1 << 22
#define LB_FLOWQOS_MAX_OFFLOAD_CT 1 << 21 ///< maximum amount of conns can be offloaded, CPS-Test 1 << 21
#define LB_PIPE_MAX_OFFLOAD_CT 1 << 21    ///< maximum amount of entries in doca-flow pipe, CPS-Test 1 << 21

RTE_DEFINE_PER_LCORE(struct rte_hash *, _ST); ///< threadLocal hash tables storing contexts of virtual servers
#define ST RTE_PER_LCORE(_ST)

/**
 * @brief context of virtual server
 *
 */
struct SERVICE
{
    /*********************Key*********************/
    uint16_t dport;
    uint16_t proto;
    uint32_t dip;
    /*********************Key*********************/
    uint32_t totalRealServers;
    uint32_t totalConnections;
    uint32_t flowStats[MAX_RIP_PER_VIP]; ///< amount of conns to this real server
    uint32_t rip[MAX_RIP_PER_VIP];
    uint32_t rport[MAX_RIP_PER_VIP];
} __rte_cache_aligned;

/**
 * @brief attributes of LB
 *
 */
struct LB_ATTR
{
    struct FlowQoS_PIPE *TCP_DownStreamPIPE;
    struct FlowQoS_PIPE *UDP_DownStreamPIPE;
    struct FlowQoS_PIPE *RSS_PIPE;
    uint64_t TCP_MatchFlags;
    uint64_t UDP_MatchFlags;
    uint64_t actionFlags;
    uint64_t cc[MAX_CORES];   ///< used to calculate cps
    struct SERVICE *services; ///< used to find memory storing services
    int servicesAmount;
    int WAN_PORT_ID;
    int LAN_PORT_ID;
} attr = {0};

/**
 * @brief critical function of LB 
 * 
 * @param newEntry 
 * @return packet_action 
 */
packet_action newConn_handler(struct FlowQoS_ENTRY *newEntry)
{
    int port_id = newEntry->pipe->port_id;
    if (port_id == attr.WAN_PORT_ID)
    {
        uint8_t mac[6];
        struct SERVICE stmp = {0}, *ser = NULL;
        stmp.dport = newEntry->match.dst_port;
        stmp.dip = newEntry->match.dst_ip;
        stmp.proto = newEntry->match.proto;
        newEntry->expireTime = CONN_EXPIRE;
        // newEntry->priority = 0;
        int ret = rte_hash_lookup_data(ST, (void *)&stmp, (void **)&ser);
        if (ret < 0)
        {
            DOCA_LOG_ERR("Not Find Service");
            return IGNORE_PACKETS;
        }

        int Rserver = (ser->totalConnections++) % ser->totalRealServers;
        newEntry->action.dst_ip = ser->rip[Rserver];
        newEntry->action.dst_port = ser->rport[Rserver];
        newEntry->action.src_ip = Rserver; // Use this field to record the target RIP inorder to age conn more quickly
        flowQoS_router_getPortMac(attr.LAN_PORT_ID, mac);
        rte_memcpy(newEntry->action.src_mac, mac, DOCA_ETHER_ADDR_LEN);

        if (flowQoS_router_get_arp(attr.LAN_PORT_ID, rte_be_to_cpu_32(newEntry->action.dst_ip), mac))
        {
            rte_memcpy(newEntry->action.dst_mac, mac, DOCA_ETHER_ADDR_LEN);
            // struct EntryInfo info;
            // dumpFlowQoSEntry(newEntry, &info);
            // printFlowQoSEntry(&info);
            ser->flowStats[Rserver]++;
            attr.cc[rte_lcore_id()]++;
            return attr.LAN_PORT_ID;
        }
        DOCA_LOG_ERR("Not Find ARP");
        return IGNORE_PACKETS;
    }
    DOCA_LOG_ERR("Not Find Service");
    return IGNORE_PACKETS;
}

/**
 * @brief used to handle aged conns
 * 
 * @param newEntry 
 */
void agingConn_handler(struct FlowQoS_ENTRY *newEntry)
{
    struct SERVICE stmp = {0}, *ser = NULL;
    stmp.dport = newEntry->match.dst_port;
    stmp.dip = newEntry->match.dst_ip;
    stmp.proto = newEntry->match.proto;
    int ret = rte_hash_lookup_data(ST, (void *)&stmp, (void **)&ser);
    if (ret < 0)
    {
        DOCA_LOG_ERR("Not Find Service");
        return;
    }
    ser->flowStats[newEntry->action.src_ip]--;
}

/**
 * @brief slave core of ipvsadm cmd
 * 
 * @param args 
 */
void printST_slave(void *args)
{
    uint32_t *stats = args;
    uint32_t iter = 0;
    uint64_t *match;
    struct SERVICE *service;
    int sid = 0;
    while (true)
    {
        int ret = rte_hash_iterate(ST, (const void **)&match, (void **)&service, (uint32_t *)&iter);
        if (ret < 0)
            break;
        for (int j = 0; j < service->totalRealServers; j++)
        {
            stats[rte_lcore_id() * MAX_RIP_PER_VIP * MAX_SERVICE + sid * MAX_RIP_PER_VIP + j] = service->flowStats[j];
        }
        sid++;
    }
}
/**
 * @brief master core of ipvsadm cmd
 * 
 * @param args 
 */
void printST(struct cmdline *cl)
{

    uint64_t *match;
    struct SERVICE *service;
    uint32_t iter = 0;
    int sid = 0;
    static uint32_t stats[MAX_RIP_PER_VIP * MAX_SERVICE * MAX_CORES] = {0};
    flowQoS_message_multiThread_do(printST_slave, (void *)stats);

    cmdline_printf(cl, "%-6s%-24s%s\n", "Proto", "LocalAddress:Port", "Schduler");
    cmdline_printf(cl, "%6s%-24s%-12s\n", "->", "RemoteAddress:Port", "ActiveCon");
    while (true)
    {
        int ret = rte_hash_iterate(ST, (const void **)&match, (void **)&service, (uint32_t *)&iter);
        if (ret < 0)
            break;
        void getAddre(char *buf, uint32_t dip, uint16_t dport)
        {
            dip = htonl(dip);
            dport = rte_be_to_cpu_16(dport);
            sprintf(buf, "%d.%d.%d.%d:%d",
                    (dip & 0xff000000) >> 24,
                    (dip & 0x00ff0000) >> 16,
                    (dip & 0x0000ff00) >> 8,
                    (dip & 0x000000ff),
                    dport);
        }
        char *proto = service->proto == 6 ? "TCP" : "UDP";
        char ADDR[23];
        getAddre(ADDR, service->dip, service->dport);
        cmdline_printf(cl, "%-6s%-24s%s\n", proto, ADDR, "RR");
        for (int j = 0; j < service->totalRealServers; j++)
        {
            getAddre(ADDR, service->rip[j], service->rport[j]);
            service->flowStats[j] = 0;
            for (int i = 0; i < MAX_CORES; i++)
            {
                service->flowStats[j] += stats[i * MAX_RIP_PER_VIP * MAX_SERVICE + sid * MAX_RIP_PER_VIP + j];
            }
            cmdline_printf(cl, "%6s%-24s%-12d\n", "->", ADDR, service->flowStats[j]);
        }
        sid++;
    }
}

/**
 * @brief print cps of LB
 * 
 * @param cl 
 */
void getCPS(struct cmdline *cl)
{
    for (int i = 0; i < 20; i++)
    {
        uint64_t _cps = 0, cps = 0, _o_cps = 0, o_cps = 0;
        for (int i = 0; i < MAX_CORES; i++)
        {
            _cps += attr.cc[i];
        }
        _o_cps = getFlowQoSOffload();
        rte_delay_ms(1000);
        for (int i = 0; i < MAX_CORES; i++)
        {
            cps += attr.cc[i];
        }
        o_cps = getFlowQoSOffload();
        cmdline_printf(cl, "CPS:%lu===>offloadCPS:%lu\n", cps - _cps, o_cps - _o_cps);
    }
}

/**
 * @brief load services into ST
 * 
 * @param dummy 
 * @return int 
 */
int load_params_to_st(__rte_unused void *dummy)
{
    uint64_t *args = dummy; // 0:ret,1:servicesAmount,2:services
    char stName[20];
    sprintf(stName, "ST-%d", rte_lcore_id());
    const struct rte_hash_parameters ServiceTable =
        {
            .name = stName,
            .entries = MAX_SERVICE,
            .reserved = 0,
            .key_len = sizeof(uint64_t),
            .hash_func = rte_jhash,
            .hash_func_init_val = 0,
            .socket_id = rte_socket_id(),
            .extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE, // 0,
        };

    ST = rte_hash_create(&ServiceTable);
    if (!ST)
    {
        DOCA_LOG_ERR("Core %d Create ST fail!", rte_lcore_id());
        return 0;
    }
    uint64_t servicesAmount = args[1];
    struct SERVICE *services = (struct SERVICE *)rte_malloc(NULL, servicesAmount * sizeof(struct SERVICE), 0);
    rte_memcpy(services, (struct SERVICE *)args[2], servicesAmount * sizeof(struct SERVICE));
    for (int i = 0; i < servicesAmount; i++)
    {
        int ret = rte_hash_add_key_data(ST, &(services[i]), &(services[i]));
        if (ret < 0)
        {
            DOCA_LOG_ERR("Failed to add a service into Core[%d] ST...", rte_lcore_id());
            return 0;
        }
    }
    DOCA_LOG_INFO("Core[%d] ST init Success!!!", rte_lcore_id());
    args[0]++;
    return 0;
}

/****************************ipvsadm******************************/

/**
 * @brief cmds of LB
 * 
 */
struct cmd_ipvsadm
{
    cmdline_fixed_string_t cmd;
};

static void cmd_ipvsadm_parsed(__rte_unused void *parsed_result,
                               struct cmdline *cl,
                               __rte_unused void *data)
{
    struct cmd_ipvsadm *res = parsed_result;
    if (strcmp(res->cmd, "ipvsadm") == 0)
        printST(cl);
    else
        getCPS(cl);
}

cmdline_parse_token_string_t cmd_ipvsadm_cmd =
    TOKEN_STRING_INITIALIZER(struct cmd_ipvsadm, cmd, "ipvsadm#cps");

cmdline_parse_inst_t cmd_ipvsadm_obj = {
    .f = cmd_ipvsadm_parsed, /* function to call */
    .data = NULL,            /* 2nd arg of func */
    .help_str = "Output connections of each RealServer or print cps of LB",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&cmd_ipvsadm_cmd,
        NULL,
    },
};

/**
 * @brief register cmds of LB into dpdk cmdline
 * 
 */
void registerLBCmd()
{
    static bool cmdRegistered = false;
    if (!cmdRegistered)
    {
        flowQoS_registCmd(&cmd_ipvsadm_obj);
        cmdRegistered = true;
        DOCA_LOG_INFO("Register ipvsadm cmd");
    }
}

/****************************ipvsadm******************************/

/**
 * @brief init params of services and down stream doca-flow pipe
 * 
 * @return int 
 */
int LB_load_params()
{
    flowQoS_router_ifconfig("dpdk0", RTE_IPV4(192, 168, 200, 2), 24);
    flowQoS_router_ifconfig("dpdk1", RTE_IPV4(192, 168, 201, 2), 24);
    uint8_t mac1[6] = {0x08, 0xc0, 0xeb, 0xbf, 0xef, 0x9a},
            mac2[6] = {0x08, 0xc0, 0xeb, 0xbf, 0xef, 0x82},
            mac3[6] = {0xb8, 0xce, 0xf6, 0xd5, 0xd6, 0xf7},
            mac4[6] = {0xb8, 0xce, 0xf6, 0xd5, 0xcc, 0x5f},
            WanMac[6] = {0x08, 0xc0, 0xeb, 0xbf, 0xef, 0x83};

    flowQoS_router_put_arp(attr.LAN_PORT_ID, RTE_IPV4(192, 168, 200, 1), mac2);
    flowQoS_router_put_arp(attr.LAN_PORT_ID, RTE_IPV4(192, 168, 200, 102), mac3);
    flowQoS_router_put_arp(attr.LAN_PORT_ID, RTE_IPV4(192, 168, 200, 103), mac4);
    flowQoS_router_setPortMac(attr.LAN_PORT_ID, mac1);

    int servicesAmount = 3;
    struct SERVICE services[3] =
        {
            {.totalRealServers = 2,
             .dip = rte_cpu_to_be_32(RTE_IPV4(192, 168, 201, 2)),
             .dport = rte_cpu_to_be_16(80),
             .proto = 6, // 6:TCP,17:UDP
             .rip = {rte_cpu_to_be_32(RTE_IPV4(192, 168, 200, 102)), rte_cpu_to_be_32(RTE_IPV4(192, 168, 200, 103))},
             .rport = {rte_cpu_to_be_16(80), rte_cpu_to_be_16(80)},
             .flowStats = {0}},
            {.totalRealServers = 2,
             .dip = rte_cpu_to_be_32(RTE_IPV4(192, 168, 201, 2)),
             .dport = rte_cpu_to_be_16(5001),
             .proto = 17,
             .rip = {rte_cpu_to_be_32(RTE_IPV4(192, 168, 200, 102)), rte_cpu_to_be_32(RTE_IPV4(192, 168, 200, 103))},
             .rport = {rte_cpu_to_be_16(5001), rte_cpu_to_be_16(5001)},
             .flowStats = {0}},
            {.totalRealServers = 2,
             .dip = rte_cpu_to_be_32(RTE_IPV4(192, 168, 201, 2)),
             .dport = rte_cpu_to_be_16(5001),
             .proto = 6,
             .rip = {rte_cpu_to_be_32(RTE_IPV4(192, 168, 200, 102)), rte_cpu_to_be_32(RTE_IPV4(192, 168, 200, 103))},
             .rport = {rte_cpu_to_be_16(5001), rte_cpu_to_be_16(5001)},
             .flowStats = {0}},
        };
    uint64_t args[3] = {0, servicesAmount, (uint64_t)&services};
    unsigned int lcore_id = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        rte_eal_remote_launch(load_params_to_st, (void *)args, lcore_id);
        rte_eal_wait_lcore(lcore_id);
    }
    load_params_to_st((void *)args);
    if (args[0] != rte_lcore_count())
    {

        DOCA_LOG_ERR("LB_load_params Fail");
        return 0;
    }

    for (int i = 0; i < servicesAmount; i++)
    {
        for (int j = 0; j < services[i].totalRealServers; j++)
        {
            struct FlowQoS_ENTRY entry = {0};
            struct FlowQoS_PIPE *pipe = NULL;
            if (services[i].proto == 6)
            {
                entry.match.flags = attr.TCP_MatchFlags;
                pipe = attr.TCP_DownStreamPIPE;
            }
            else
            {
                entry.match.flags = attr.UDP_MatchFlags;
                pipe = attr.UDP_DownStreamPIPE;
            }
            entry.match.src_ip = services[i].rip[j];
            entry.match.src_port = services[i].rport[j];
            entry.action.flags = attr.actionFlags;
            entry.action.src_ip = services[i].dip;
            entry.action.src_port = services[i].dport;
            uint8_t localMac[6];
            flowQoS_router_getPortMac(attr.WAN_PORT_ID, localMac);
            rte_memcpy(entry.action.src_mac, localMac, DOCA_ETHER_ADDR_LEN);
            rte_memcpy(entry.action.dst_mac, WanMac, DOCA_ETHER_ADDR_LEN);

            int ret = flowQoS_add_entry(pipe, &(entry), 0, 1);
            if (ret)
            {
                struct EntryInfo info;
                dumpFlowQoSEntry(&entry, &info);
                printFlowQoSEntry(&info);
            }
            else
            {
                DOCA_LOG_ERR("LB_load_params Fail");
                return 0;
            }
        }
    }
    registerLBCmd();
    DOCA_LOG_INFO("LB_load_params Success");
    return 1;
}

/**
 * @brief init LB
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int LB_init(int argc, char **argv)
{
    flowQoS_env_init(argc, argv);
    struct FlowQoS_ENTRY rssEntry = {0};

    attr.TCP_MatchFlags = SIP | SPORT | TCP;
    attr.UDP_MatchFlags = SIP | SPORT | UDP;
    attr.actionFlags = SIP | SPORT | TTL_DECREASE | SMAC | DMAC;
    attr.WAN_PORT_ID = 1;
    attr.LAN_PORT_ID = 0;

    attr.RSS_PIPE = flowQoS_build_pipe(attr.LAN_PORT_ID, "LAN-RSS", 0, 0, RSS_TO_QUEUE, DROP, !IS_ROOT, 2);
    int ret = flowQoS_add_entry(attr.RSS_PIPE, &(rssEntry), 0, 1);
    attr.TCP_DownStreamPIPE = flowQoS_build_pipe(attr.LAN_PORT_ID, "LAN-TCP", attr.TCP_MatchFlags, attr.actionFlags, PORT, (FlowQoS_FWD)(attr.RSS_PIPE), IS_ROOT, 100);
    attr.UDP_DownStreamPIPE = flowQoS_build_pipe(attr.LAN_PORT_ID, "LAN-UDP", attr.UDP_MatchFlags, attr.actionFlags, PORT, (FlowQoS_FWD)(attr.RSS_PIPE), IS_ROOT, 100);

    if (ret <= 0 || attr.RSS_PIPE == NULL || attr.TCP_DownStreamPIPE == NULL || attr.UDP_DownStreamPIPE == NULL)
        return 0;
    if (flowQoS_conntrack_init_env(LB_MAX_CT, LB_FLOWQOS_MAX_OFFLOAD_CT, FLOWQOS_DELAY, FLOWQOS_OFFLOAD_SPEED) <= 0)
        return 0;
    if (flowQoS_conntrack_init_port(attr.WAN_PORT_ID, LB_PIPE_MAX_OFFLOAD_CT, DPORT | DIP | SMAC | TTL_DECREASE | DMAC | AGING) < 0)
        return 0;

    registRoutingModule(true);
    register_packet_processor(flowQoS_ARP_ICMP_PROCESS);
    flowQoS_regist_newConn_handler(newConn_handler);
    flowQoS_regist_agingConn_handler(agingConn_handler);

    return LB_load_params();
}

/**
 * @brief release resources of LB
 * 
 */
void LB_exit()
{
    flowQoS_env_destroy();
}

int main(int argc, char **argv)
{

    if (LB_init(argc, argv) == 0)
        goto EXIT;

    launch_worker();
    flowQoS_cmd();
    stop_worker();

EXIT:
    LB_exit();
    return 0;
}