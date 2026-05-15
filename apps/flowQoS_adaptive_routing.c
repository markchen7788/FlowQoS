/**
 * @file flowQoS_adptive_routing.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief Adaptive routing based on flowQoS
 * @version 0.1
 * @date 2024-01-22
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

DOCA_LOG_REGISTER(FLOWQOS_ADAPTIVE_ROUTING);

/*** OvS flow for sending back probe packets
ovs-ofctl del-flows ovsbr1
ovs-ofctl add-flow ovsbr1 "priority=300,in_port=p0,udp,tp_dst=4789,nw_tos=0x20 actions=mod_dl_dst:08:c0:eb:bf:ef:9a,mod_tp_dst:4788,output:IN_PORT"
ovs-ofctl add-flow ovsbr1 "priority=100,in_port=p0 actions=output:pf0hpf"
ovs-ofctl add-flow ovsbr1 "priority=100,in_port=pf0hpf actions=output:p0"
*/

#define HOST_PORT 0                     ///< id of port to host
#define DST_PORT 1                      ///< id of port to network
#define PROBE_PATH_AMOUNT 4             ///< amount of paths we probed
static struct rte_mempool *pool = NULL; ///< packet mempool
static uint64_t flowID = 0;             ///< id of new flow

uint8_t mac1[6] = {0x08, 0xc0, 0xeb, 0xbf, 0xef, 0x9a}, // CQ-p0
    mac2[6] = {0x08, 0xc0, 0xeb, 0xbf, 0xef, 0x82},     // YY-p0
    mac3[6] = {0xb8, 0xce, 0xf6, 0xd5, 0xd6, 0xf7},     // Node2-p1
    mac4[6] = {0xb8, 0xce, 0xf6, 0xd5, 0xcc, 0x5f};     // Node3-p1

struct PROBE_HDR
{
    uint64_t timeStamp; ///< timestamp when we sent
    uint64_t FlowID;    ///< id of flow this packet belongs to
};

/**
 * @brief adaptive routing algorithm, which is based on min-RTT
 *
 * @param newEntry
 * @return uint16_t
 */
uint16_t adaptive_routing(struct FlowQoS_ENTRY *newEntry)
{

    struct rte_mbuf *mbufs[PROBE_PATH_AMOUNT];
    int count = rte_pktmbuf_alloc_bulk(pool, mbufs, PROBE_PATH_AMOUNT) == 0 ? PROBE_PATH_AMOUNT : 0;
    int port_id = (newEntry->pipe->port_id) ^ 1;
    flowID++;
    for (int p = 0; p < count; p++)
    {
        struct rte_ether_hdr *ether_h;
        struct rte_ipv4_hdr *ip;
        struct rte_udp_hdr *udp_h;
        struct PROBE_HDR *pay;
        /**Ether**/
        ether_h = (struct rte_ether_hdr *)rte_pktmbuf_append(mbufs[p], sizeof(struct rte_ether_hdr));
        rte_memcpy(ether_h->s_addr.addr_bytes, mac1, RTE_ETHER_ADDR_LEN);
        rte_memcpy(ether_h->d_addr.addr_bytes, mac2, RTE_ETHER_ADDR_LEN);
        ether_h->ether_type = rte_cpu_to_be_16(0x0800);
        /**IP**/
        ip = (struct rte_ipv4_hdr *)rte_pktmbuf_append(mbufs[p], sizeof(struct rte_ipv4_hdr));
        ip->version_ihl = 0x45;
        ip->type_of_service = 0x20;
        ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(struct PROBE_HDR));
        ip->packet_id = 0;
        ip->fragment_offset = 0;
        ip->time_to_live = 64; // ttl = 64
        ip->next_proto_id = IPPROTO_UDP;
        ip->src_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 200, 2));
        ip->dst_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 200, 1));
        ip->hdr_checksum = 0;
        /**UDP**/
        udp_h = (struct rte_udp_hdr *)rte_pktmbuf_append(mbufs[p], sizeof(struct rte_udp_hdr));
        udp_h->src_port = rte_cpu_to_be_16(rte_be_to_cpu_16(newEntry->match.src_port) + p);
        udp_h->dst_port = rte_cpu_to_be_16(4789);
        udp_h->dgram_cksum = 0;
        udp_h->dgram_len = rte_cpu_to_be_16(sizeof(struct PROBE_HDR));
        /**Payload**/
        pay = (struct PROBE_HDR *)rte_pktmbuf_append(mbufs[p], sizeof(struct PROBE_HDR));
        pay->timeStamp = rte_rdtsc();
        pay->FlowID = flowID;
        /**offload cksum**/
        mbufs[p]->l2_len = sizeof(struct rte_ether_hdr);
        mbufs[p]->l3_len = sizeof(struct rte_ipv4_hdr);
        mbufs[p]->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
    }
    int nb_tx = rte_eth_tx_burst(port_id, 0, mbufs, count);
    // DOCA_LOG_INFO("Sent %d Probe Packets", count);
    if (unlikely(nb_tx < count))
    {
        do
        {
            rte_pktmbuf_free(mbufs[nb_tx]);
        } while (++nb_tx < count);
    }

    uint64_t start = rte_rdtsc(), gap = rte_get_tsc_hz() / 100;
    while (rte_rdtsc() - start < gap)
    {
        int nb_rx = rte_eth_rx_burst(port_id, 0, mbufs, PROBE_PATH_AMOUNT);
        for (int i = 0; i < nb_rx; i++)
        {
            struct rte_mbuf *m = mbufs[i];
            if (RTE_ETH_IS_IPV4_HDR(m->packet_type))
            {
                struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                if (ip->next_proto_id == 17)
                {
                    struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
                    if (udp->dst_port == rte_cpu_to_be_16(4788))
                    {
                        uint16_t res = udp->src_port;
                        struct PROBE_HDR *hdr = rte_pktmbuf_mtod_offset(m, struct PROBE_HDR *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
                        if (hdr->FlowID == flowID)
                        {
                            rte_pktmbuf_free(m);
                            return res;
                        }
                    }
                }
            }
            rte_pktmbuf_free(m);
        }
    }
    DOCA_LOG_ERR("Not Find Best Path for Not Received Probe Packets");
    return 0;
}
/**
 * @brief callback of handling new conn
 *
 * @param newEntry
 * @return packet_action
 */
packet_action newConn_handler(struct FlowQoS_ENTRY *newEntry)
{

    // struct EntryInfo info;
    // dumpFlowQoSEntry(newEntry, &info);
    // printFlowQoSEntry(&info);
    int port_id = newEntry->pipe->port_id;
    if (port_id == HOST_PORT && newEntry->match.dst_port == rte_cpu_to_be_16(4789))
    {
        newEntry->expireTime = 60;
        uint16_t bestPath = adaptive_routing(newEntry);
        DOCA_LOG_INFO("Origin Path: %d Best Path:%d", rte_be_to_cpu_16(newEntry->match.src_port), rte_be_to_cpu_16(bestPath));
        if (bestPath)
        {
            newEntry->action.src_port = bestPath;
            return port_id ^ 1;
        }
    }
    return IGNORE_PACKETS;
}

int main(int argc, char **argv)
{
    flowQoS_env_init(argc, argv);

    if (rte_lcore_count() == 2)
    {
        /*************DOCA-AR*****************/
        if (flowQoS_conntrack_init_env(1024, 0, 0, 0) <= 0)
            goto EXIT;
        if (flowQoS_conntrack_init_port(HOST_PORT, 1024, SPORT | AGING) < 0)
            goto EXIT;

        struct FlowQoS_ENTRY offloadentry = {0}, entry = {0};
        struct FlowQoS_PIPE *offload_pipe = flowQoS_build_pipe(DST_PORT, "FWD-PIPE", 0, COUNTER, PORT, DROP, !IS_ROOT, 10000);
        if (offload_pipe == NULL)
            goto EXIT;
        int ret = flowQoS_add_entry(offload_pipe, &(offloadentry), 0, 1);
        if (ret)
        {
            struct EntryInfo info;
            dumpFlowQoSEntry(&offloadentry, &info);
            printFlowQoSEntry(&info);
        }
        else
        {
            DOCA_LOG_ERR("Create PROBE Entry Fail");
            goto EXIT;
        }

        struct FlowQoS_PIPE *pipe = flowQoS_build_pipe(DST_PORT, "PROBE-PIPE", DIP | UDP | DPORT, COUNTER, RSS_TO_QUEUE, (FlowQoS_FWD)offload_pipe, IS_ROOT, 10000);
        if (pipe == NULL)
            goto EXIT;
        memset(&entry, 0, sizeof(entry));
        entry.match.dst_ip = rte_cpu_to_be_32(RTE_IPV4(192, 168, 200, 1));
        entry.match.dst_port = rte_cpu_to_be_16(4788);
        ret = flowQoS_add_entry(pipe, &(entry), 0, 1);
        if (ret)
        {
            struct EntryInfo info;
            dumpFlowQoSEntry(&entry, &info);
            printFlowQoSEntry(&info);
        }
        else
        {
            DOCA_LOG_ERR("Create PROBE Entry Fail");
            goto EXIT;
        }

        flowQoS_regist_newConn_handler(newConn_handler);
        pool = rte_mempool_lookup("MBUF_POOL");
        if (pool == NULL)
            goto EXIT;
        // rte_mempool_dump(stdout, pool);

        launch_worker();
        DOCA_LOG_INFO("Running DOCA-AR");
        flowQoS_cmd();
        stop_worker();
    }
    else
    {
        /*************ECMP*****************/
        char *name[2] = {"fwd0", "fwd1"};
        for (int port = 0; port < 2; port++)
        {
            struct FlowQoS_PIPE *pipe = flowQoS_build_pipe(port, name[port], 0, 0, PORT, DROP, IS_ROOT, 100);
            if (pipe == NULL)
                goto EXIT;
            struct FlowQoS_ENTRY entry = {0};
            int ret = flowQoS_add_entry(pipe, &(entry), 0, 1);
            if (ret)
            {
                struct EntryInfo info;
                dumpFlowQoSEntry(&entry, &info);
                printFlowQoSEntry(&info);
            }
        }
        DOCA_LOG_INFO("Running ECMP");
        flowQoS_cmd();
    }

EXIT:
    flowQoS_env_destroy();
    return 0;
}