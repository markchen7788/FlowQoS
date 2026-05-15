/**
 * @file flowQoS_vxlan_packets_spraying.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief vxlan packets spraying
 * @version 0.1
 * @date 2024-01-22
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <stdio.h>
#include "flowQoS_env.h"
#include "flowQoS_pipe.h"
#include "flowQoS_worker.h"
#include "flowQoS_cmd.h"
DOCA_LOG_REGISTER(FLOWQOS_VXLAN_PACKETS_SPRAYING);

RTE_DEFINE_PER_LCORE(uint64_t, _counter); ///< threadLocal variable recording amount of packets
#define counter RTE_PER_LCORE(_counter)

/**
 * @brief function of packets spraying
 * 
 * @param packet 
 * @return packet_action 
 */
packet_action packet_spray(struct rte_mbuf *packet)
{
    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(packet, struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    uint16_t vPaths[4]={7788,7789,7788,7789};
    counter++;
    // DOCA_LOG_INFO("Get UDP Packet on core %d, change Sport From %d To %lu!", rte_lcore_id(), rte_be_to_cpu_16(udp_hdr->src_port), counter % 100);
    //udp_hdr->src_port = rte_cpu_to_be_16(vPaths[counter % 4]); // Packet Spray
    udp_hdr->src_port = rte_cpu_to_be_16(counter % 4 + 7788);
    packet->ol_flags |= PKT_TX_UDP_CKSUM;
    udp_hdr->dgram_cksum = 0;
    return packet->port ^ 1;
}

int main(int argc, char **argv)
{
    flowQoS_env_init(argc, argv);
    struct FlowQoS_PIPE *pipe[2];
    struct FlowQoS_ENTRY entry[2];
    char *pipe_name[] = {"upstreamPipe", "downstreamPipe"};
    uint64_t matchFlags = DIP | UDP, actionFlags = COUNTER;
    memset(entry, 0, sizeof(entry));
    for (int i = 0; i < 2; i++)
    {
        pipe[i] = flowQoS_build_pipe(i, pipe_name[i], matchFlags, actionFlags, RSS_TO_QUEUE, DROP, IS_ROOT, 10);
        if (i == 1)
        {
            entry[i].match.dst_ip = BE_IPV4_ADDR(192, 168, 200, 2);
        }
        else
        {
            entry[i].match.dst_ip = BE_IPV4_ADDR(192, 168, 200, 1);
        }
        entry[i].match.flags = matchFlags;
        entry[i].action.flags = actionFlags;
        flowQoS_add_entry(pipe[i], &(entry[i]), 0, 1);
    }

    register_packet_processor(packet_spray); // Register pkt processor

    launch_worker();
    flowQoS_cmd();
    stop_worker();

    flowQoS_env_destroy();
    return 0;
}
