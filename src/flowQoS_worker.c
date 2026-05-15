/**
 * @file flowQoS_worker.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief slave workers module handling registered abstract tasks including sending and receving rte_mbuf, which is inspired by dpvs
 * @version 0.1
 * @date 2024-01-22
 *
 * @copyright Copyright (c) 2024
 *
 */
#include "flowQoS_worker.h"
#include "flowQoS_cmd.h"
#include "flowQoS_message.h"
#include <doca_log.h>

DOCA_LOG_REGISTER(FLOWQOS_WORKER);
static volatile bool force_quit = true;                         ///< flag of quit
static volatile int packet_processor_num = 0;                   ///< amount of tasks processing packets
static volatile int general_processor_num = 1;                  ///< amount of general tasks including a default task procssing packets
packet_processor packet_processor_arr[MAX_PROCESSOR_NUM];       ///< packet tasks array
general_processor general_processor_arr[MAX_PROCESSOR_NUM];     ///< general tasks array
char general_processor_name_arr[MAX_PROCESSOR_NUM][30];         ///< name of general task
uint64_t cpuConsumption[MAX_CORES][MAX_PROCESSOR_NUM] = {0};    ///< cpu consumption of tasks per-core
double cpuConsumptionStats[MAX_CORES][MAX_PROCESSOR_NUM] = {0}; ///< cpu consumption rate of tasks per-core

/**
 * @brief register cmds of worker module into dpdk-cmdline
 *
 */
void registerWorkerCmd();

/**
 * @brief context of slave worker
 *
 */
struct Lcore_conf
{
    int port_num;    ///< total num of dpdk ports
    int queue_id;    ///< the packets queue this worker should manage
    int FlowQueueId; ///< the doca-flow queue this worker should manage
    struct QueuesBuf
    {
        struct rte_mbuf *rx_burst[MAX_PKT_BURST];
        struct rte_mbuf *tx_burst[MAX_PKT_BURST];
        int rx_len;
        int tx_len;
    } queuesBuf[MAX_ETHPORTS]; ///< QueuesBuf having same Id and from different ports
} __rte_cache_aligned lcore_conf[MAX_CORES];

/**
 * @brief send packets if tx_buf is full or put it to tx_buf
 *
 * @param port_id
 * @param cid
 * @param m
 * @return int
 */
int send_packets(int port_id, int cid, struct rte_mbuf *m)
{
    int nb_tx = 0;
    if (lcore_conf[cid].queuesBuf[port_id].tx_len == MAX_PKT_BURST)
    {
        nb_tx = rte_eth_tx_burst(port_id, lcore_conf[cid].queue_id, lcore_conf[cid].queuesBuf[port_id].tx_burst, MAX_PKT_BURST);
        if (unlikely(nb_tx < MAX_PKT_BURST))
        {
            // RTE_LOG(INFO, USER1, "Flush Core %d Port %d Queue %d TX_LEN %d\n", cid, port_id, lcore_conf[cid].queue_id, lcore_conf[cid].queuesBuf[port_id].tx_len);
            do
            {
                rte_pktmbuf_free(lcore_conf[cid].queuesBuf[port_id].tx_burst[nb_tx]);
            } while (++nb_tx < MAX_PKT_BURST);
        }
        lcore_conf[cid].queuesBuf[port_id].tx_len = 0;
    }
    // RTE_LOG(INFO, USER1, "Put at core-%d:port-%d:queue-%d:pos:%d\n", cid, port_id, lcore_conf[cid].queue_id, lcore_conf[cid].queuesBuf[port_id].tx_len);
    lcore_conf[cid].queuesBuf[port_id].tx_burst[lcore_conf[cid].queuesBuf[port_id].tx_len] = m;
    lcore_conf[cid].queuesBuf[port_id].tx_len++;
    // RTE_LOG(INFO, USER1, "Core %d Port %d Queue %d TX_LEN %d\n", cid, port_id, lcore_conf[cid].queue_id, lcore_conf[cid].queuesBuf[port_id].tx_len);
    return nb_tx;
}
/**
 * @brief general task running packet tasks
 *
 * @param cid
 * @return int
 */
static int general_pkt_processor(int cid)
{
    int ret = 0;
    for (int port_id = 0; port_id < lcore_conf[cid].port_num; port_id++)
    {
        lcore_conf[cid].queuesBuf[port_id].rx_len = rte_eth_rx_burst(port_id, lcore_conf[cid].queue_id, lcore_conf[cid].queuesBuf[port_id].rx_burst, PACKET_BURST);
        for (int i = 0; i < lcore_conf[cid].queuesBuf[port_id].rx_len; i++)
        {
            packet_action action = DROP_PACKETS; // default action
            for (int job = 0; job < packet_processor_num; job++)
            {
                packet_action this_action = packet_processor_arr[job](lcore_conf[cid].queuesBuf[port_id].rx_burst[i]);
                if (this_action != IGNORE_PACKETS)
                {
                    action = this_action;
                }
            }
            if (action == DROP_PACKETS)
            {
                // RTE_LOG(INFO, USER1, "Port %d DROP\n", lcore_conf[cid].queuesBuf[port_id].rx_burst[i]->port);
                rte_pktmbuf_free(lcore_conf[cid].queuesBuf[port_id].rx_burst[i]);
            }
            else
            {
                // RTE_LOG(INFO, USER1, "Port %d Send  Port %d\n", lcore_conf[cid].queuesBuf[port_id].rx_burst[i]->port, action);
                // int num =
                send_packets(action, cid, lcore_conf[cid].queuesBuf[port_id].rx_burst[i]);
                // RTE_LOG(INFO, USER1, "Send Packets:%d\n", num);
            }
            ret++;
        }
        ret += lcore_conf[cid].queuesBuf[port_id].tx_len;
        int nb_tx = rte_eth_tx_burst(port_id, lcore_conf[cid].queue_id, lcore_conf[cid].queuesBuf[port_id].tx_burst, lcore_conf[cid].queuesBuf[port_id].tx_len);
        // if (nb_tx)
        //     RTE_LOG(INFO, USER1, "nb_tx:%d\n", nb_tx);
        if (unlikely(nb_tx < lcore_conf[cid].queuesBuf[port_id].tx_len))
        {
            do
            {
                rte_pktmbuf_free(lcore_conf->queuesBuf[port_id].tx_burst[nb_tx]);
            } while (++nb_tx < lcore_conf[cid].queuesBuf[port_id].tx_len);
        }
        lcore_conf[cid].queuesBuf[port_id].tx_len = 0;
    }
    return ret;
}

/**
 * @brief main function of slave workers
 *
 * @param dummy
 * @return int
 */
static int worker(__rte_unused void *dummy)
{
    FlowQoS_SYN_PRINT("Worker %d start", rte_lcore_id());
    int cid = rte_lcore_id();
    while (!force_quit)
    {
        for (int job = 0; job < general_processor_num; job++)
        {
            uint64_t stmp = rte_rdtsc();
            if (general_processor_arr[job](cid))
            {
                cpuConsumption[cid][job] += rte_rdtsc() - stmp;
            }
        }
    }
    FlowQoS_SYN_PRINT("Worker %d stop", rte_lcore_id());
    return 0;
}

int register_packet_processor(packet_processor p)
{
    if (packet_processor_num == MAX_PROCESSOR_NUM)
        return 0;
    packet_processor_arr[packet_processor_num] = p;
    packet_processor_num++;
    return 1;
}

int register_general_processor(general_processor p, char *general_processor_name)
{
    if (general_processor_num == MAX_PROCESSOR_NUM)
        return 0;
    general_processor_arr[general_processor_num] = p;
    sprintf(general_processor_name_arr[general_processor_num], "%s", general_processor_name);
    general_processor_num++;
    return 1;
}

void launch_worker()
{
    unsigned lcore_id;
    int Qid = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        if (Qid >= MAX_QUEUES)
        {
            break;
        }
        lcore_conf[lcore_id].queue_id = Qid;
        lcore_conf[lcore_id].FlowQueueId = Qid;
        lcore_conf[lcore_id].port_num = MAX_ETHPORTS;
        Qid++;
        DOCA_LOG_INFO("Assign Core %d==>Queue %d ==>FlowQueue%d", lcore_id, lcore_conf[lcore_id].queue_id, lcore_conf[lcore_id].FlowQueueId);
    }

    general_processor_arr[0] = general_pkt_processor; // Add pkt processor as default general_processor
    sprintf(general_processor_name_arr[0], "%s", "Packet");

    registerWorkerCmd();

    force_quit = false;
    rte_eal_mp_remote_launch(worker, NULL, SKIP_MAIN);
}
void stop_worker()
{
    force_quit = true;
    rte_eal_mp_wait_lcore();
}

bool is_worker_running()
{
    return !force_quit;
}

int getFlowQid(int cid)
{
    return lcore_conf[cid].FlowQueueId;
}

void dumpQueueStats(struct cmdline *cl)
{
    static struct rte_eth_stats port_now_stats[MAX_ETHPORTS] = {0}, port_last_stats[MAX_ETHPORTS] = {0};
    static uint64_t last = 0;
    double interval = (double)(rte_rdtsc() - last) / ((double)rte_get_tsc_hz() / 1000000.0);
    DOCA_LOG_INFO("=============================>DumpWorkerInfo==>");
    for (int port = 0; port < MAX_ETHPORTS; port++)
    {
        DOCA_LOG_INFO("========>Port %d==>", port);
        rte_eth_stats_get(port, &(port_now_stats[port]));
        /*QueueID RX_Bytes RX_Pkts RXBPS PPS*/
        for (int q = 0; q < rte_lcore_count() - 1; q++)
        {
            port_last_stats[port].q_ipackets[q] = port_now_stats[port].q_ipackets[q] - port_last_stats[port].q_ipackets[q];
            port_last_stats[port].q_ibytes[q] = port_now_stats[port].q_ibytes[q] - port_last_stats[port].q_ibytes[q];
            port_last_stats[port].q_opackets[q] = port_now_stats[port].q_opackets[q] - port_last_stats[port].q_opackets[q];
            port_last_stats[port].q_obytes[q] = port_now_stats[port].q_obytes[q] - port_last_stats[port].q_obytes[q];
            cmdline_printf(cl, "Queue %2d: RX-Pkts:%16lu RX-Byts:%16lu RX-Mpps:%8.2f RX-Mbps:%8.2f\n",
                           q, port_now_stats[port].q_ipackets[q], port_now_stats[port].q_ibytes[q],
                           (double)port_last_stats[port].q_ipackets[q] / interval,
                           (double)port_last_stats[port].q_ibytes[q] / interval * 8.0);

            cmdline_printf(cl, "          TX-Pkts:%16lu TX-Byts:%16lu TX-Mpps:%8.2f TX-Mbps:%8.2f\n",
                           port_now_stats[port].q_opackets[q], port_now_stats[port].q_obytes[q],
                           (double)port_last_stats[port].q_opackets[q] / interval,
                           (double)port_last_stats[port].q_obytes[q] / interval * 8.0);
        }
        port_last_stats[port].ipackets = port_now_stats[port].ipackets - port_last_stats[port].ipackets;
        port_last_stats[port].ibytes = port_now_stats[port].ibytes - port_last_stats[port].ibytes;
        port_last_stats[port].opackets = port_now_stats[port].opackets - port_last_stats[port].opackets;
        port_last_stats[port].obytes = port_now_stats[port].obytes - port_last_stats[port].obytes;
        cmdline_printf(cl, "Queue %2s: RX-Pkts:%16lu RX-Byts:%16lu RX-Mpps:%8.2f RX-Mbps:%8.2f\n",
                       "s", port_now_stats[port].ipackets, port_now_stats[port].ibytes,
                       (double)port_last_stats[port].ipackets / interval,
                       (double)port_last_stats[port].ibytes / interval * 8.0);

        cmdline_printf(cl, "          TX-Pkts:%16lu TX-Byts:%16lu TX-Mpps:%8.2f TX-Mbps:%8.2f\n",
                       port_now_stats[port].opackets, port_now_stats[port].obytes,
                       (double)port_last_stats[port].opackets / interval,
                       (double)port_last_stats[port].obytes / interval * 8.0);
        rte_eth_stats_get(port, &(port_last_stats[port]));
    }
    DOCA_LOG_INFO("=============================>DumpWorkerInfo==>");
    last = rte_rdtsc();
}
/**
 * @brief slave core of dumpWorkerStats[top cmd] API()
 *
 * @param args
 */
void dumpWorkerStats_slave(void *args)
{
    int cid = rte_lcore_id();
    for (int i = 0; i < general_processor_num; i++)
    {
        cpuConsumptionStats[cid][i] = cpuConsumption[cid][i];
        cpuConsumption[cid][i] = 0;
    }
}
/**
 * @brief master core of dumpWorkerStats[top cmd] API()
 *
 * @param cl
 */
void dumpWorkerStats(struct cmdline *cl)
{
    static uint64_t stmp = 0;

    double interval = rte_rdtsc() - stmp, all = 0;
    flowQoS_message_multiThread_do(dumpWorkerStats_slave, NULL);
    for (int i = 0; i < general_processor_num; i++)
    {
        double res = 0;
        unsigned int lcore_id;
        RTE_LCORE_FOREACH_WORKER(lcore_id)
        {
            res += cpuConsumptionStats[lcore_id][i];
        }
        res /= ((rte_lcore_count() - 1) * 1.0);
        cmdline_printf(cl, "Processor[%d]:%-10s CPU:%-10.2f%%\n", i, general_processor_name_arr[i], res * 100.0 / interval);
        all += res * 100.0 / interval;
    }
    cmdline_printf(cl, "Processor[s]:%-10s CPU:%-10.2f%%\n", "ALL", all);
    stmp = rte_rdtsc();
}

/**********************************************************/

/**
 * @brief cmds registered into dpdk cmdline, including "queue" and "top".
 *
 */
struct cmd_dumpWorker
{
    cmdline_fixed_string_t cmd;
};

static void cmd_dumpWorker_parsed(__rte_unused void *parsed_result,
                                  struct cmdline *cl,
                                  __rte_unused void *data)
{
    struct cmd_dumpWorker *res = parsed_result;
    if (strcmp(res->cmd, "top") == 0)
    {
        dumpWorkerStats(cl);
    }
    if (strcmp(res->cmd, "queue") == 0)
    {
        dumpQueueStats(cl);
    }
}

cmdline_parse_token_string_t cmd_dumpWorker_cmd =
    TOKEN_STRING_INITIALIZER(struct cmd_dumpWorker, cmd, "top#queue");

cmdline_parse_inst_t cmd_dumpWorker_obj = {
    .f = cmd_dumpWorker_parsed, /* function to call */
    .data = NULL,               /* 2nd arg of func */
    .help_str = "Output CPU util or number of received and sent packets",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&cmd_dumpWorker_cmd,
        NULL,
    },
};
/**
 * @brief register cmds of this module into dpdk cmdline, including "queue" and "top".
 * 
 */
void registerWorkerCmd()
{
    static bool cmdRegistered = false;
    if (!cmdRegistered)
    {
        flowQoS_registCmd(&cmd_dumpWorker_obj);
        cmdRegistered = true;
        DOCA_LOG_INFO("Register dumpWorker cmd");
    }
}
