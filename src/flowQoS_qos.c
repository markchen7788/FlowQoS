/**
 * @file flowQoS_qos.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief QoS-based scheduler for adding doca-flow entries into FDB 
 * @version 0.1
 * @date 2024-01-26
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#include "flowQoS_qos.h"
#include "flowQoS_message.h"
#include <rte_lcore.h>
#include <doca_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
DOCA_LOG_REGISTER(FLOWQOS_QOS);

RTE_DEFINE_PER_LCORE(struct FlowQoS_Stats *, _FlowQoS_Context); ///< threadLocal context of flowQoS
#define FlowQoS_Context RTE_PER_LCORE(_FlowQoS_Context)         ///< threadLocal context of flowQoS
static int PriorityQueueNum = 4;                                ///< default num of priorities
static FlowQoS_QoS_Congestion_Handler qosCongestionHandler = NULL;
static void *qosCongestionArgs = NULL;

/**
 * @brief register cmds of flowQoS module into dpdk cmdlines
 *
 */
void registerFlowQoSCmd();

/**
 * @brief init FlowQoS_Stats per-core
 *
 * @param dummy
 * @return int
 */
int initFlowQoS_Context(__rte_unused void *dummy)
{
    FlowQoS_Context = (struct FlowQoS_Stats *)rte_malloc(NULL, sizeof(struct FlowQoS_Stats), 0);
    rte_memcpy(FlowQoS_Context, (struct FlowQoS_Stats *)dummy, sizeof(struct FlowQoS_Stats));
    memset(FlowQoS_Context->buckets, 0, sizeof(FlowQoS_Context->buckets));
    for (int i = 0; i < PriorityQueueNum; i++)
    {
        TAILQ_INIT(&(FlowQoS_Context->buckets[i]));
    }
    // FlowQoS_Context->maxEntry /= (rte_lcore_count() - 1);
    return 0;
}

/**
 * @brief count flows still in priority queue
 *
 */
void FlushOnListLength()
{
    struct FlowQoS_ENTRY *entry = NULL;
    for (int i = 0; i < PriorityQueueNum; i++)
    {
        int onList = 0;
        TAILQ_FOREACH(entry, &(FlowQoS_Context->buckets[i]), index)
        onList++;
        FlowQoS_Context->onList[i] = onList;
    }
}

void flowQoS_add_entry_event(struct FlowQoS_ENTRY *entry, int priority)
{
    entry->priority = priority;
    TAILQ_INSERT_TAIL(&(FlowQoS_Context->buckets[priority]), entry, index);
    FlowQoS_Context->total[priority]++;
}

void flowQoS_del_entry_event(struct FlowQoS_ENTRY *entry)
{
    TAILQ_REMOVE(&(FlowQoS_Context->buckets[entry->priority]), entry, index); // same ctx cannot be removed twice or more times
}

void flowQoS_return_entry_event()
{
    FlowQoS_Context->maxEntry++;
    if (FlowQoS_Context->maxEntry > FlowQoS_Context->maxEntryLimit)
    {
        FlowQoS_Context->maxEntry = FlowQoS_Context->maxEntryLimit;
    }
}

void flowQoS_regist_congestion_handler(FlowQoS_QoS_Congestion_Handler handler, void *args)
{
    qosCongestionHandler = handler;
    qosCongestionArgs = args;
}

/**
 * @brief slave func running in slave cores of flowQoS module to offload flows every once in a while, which is registered into flowQoS wortker module.
 *
 * @param cid
 * @return int
 */
int flowQoS_do_entry_event(int cid)
{
    int res = 0;
    uint64_t cur = rte_rdtsc();
    if (cur - FlowQoS_Context->lastStmp > FlowQoS_Context->gap)
    {
        for (int i = FlowQoS_Context->priorityQueueNum - 1; i >= 0; i--)
        {
            int weight = FlowQoS_Context->weight[i];
            struct FlowQoS_ENTRY *entry = TAILQ_FIRST(&(FlowQoS_Context->buckets[i])), *entry_tmp;
            while (entry != NULL)
            {
                if (weight <= 0 || FlowQoS_Context->maxEntry <= 0) // if no more entry_event can be done or this priority queue has finished entry_event
                    break;

                int ret = flowQoS_add_entry(entry->pipe, entry, getFlowQid(cid), 1);

                if (ret <= 0)
                {
                    // DOCA_LOG_ERR("flowQoS_add_entry fail");
                    return 0;
                }

                res += ret;
                // do callback
                entry->flowQoS_qosHandler(entry->flowQoS_args);

                FlowQoS_Context->maxEntry--;
                FlowQoS_Context->finished[i]++;
                weight--;
                uint64_t occupied = FlowQoS_Context->maxEntryLimit - FlowQoS_Context->maxEntry;
                uint64_t watermark = FlowQoS_Context->maxEntryLimit * FlowQoS_Context->hwWatermarkPercent / 100;
                if (FlowQoS_Context->maxEntryLimit > 0 && occupied < watermark)
                {
                    FlowQoS_Context->hwCongested = 0;
                }
                if (FlowQoS_Context->maxEntryLimit > 0 && qosCongestionHandler != NULL && occupied >= watermark && !FlowQoS_Context->hwCongested)
                {
                    FlowQoS_Context->hwCongested = 1;
                    qosCongestionHandler(occupied, FlowQoS_Context->maxEntryLimit, qosCongestionArgs);
                }
                // DOCA_LOG_INFO("FlowQoS_Context->maxEntry=%d", FlowQoS_Context->maxEntry);

                entry_tmp = TAILQ_NEXT(entry, index);
                flowQoS_del_entry_event(entry);

                entry = entry_tmp;
            }
        }
        FlowQoS_Context->lastStmp = cur;
    }
    return res;
}

/**
 * @brief print stats of flowQoS module
 *
 * @param cur
 * @param flag
 * @param cl
 */
void printFlowQoS(struct FlowQoS_Stats *cur, int flag, struct cmdline *cl)
{
    switch (flag)
    {
    case 0: // get Info From Slave Core
        FlushOnListLength();
        memcpy(cur, FlowQoS_Context, sizeof(struct FlowQoS_Stats));
        break;
    case 1: // memset Main Core Info
        memset(FlowQoS_Context, 0, sizeof(struct FlowQoS_Stats));
        break;
    case 2: // add Info To Main Core
        FlowQoS_Context->priorityQueueNum = cur->priorityQueueNum;
        FlowQoS_Context->maxEntry += cur->maxEntry;
        FlowQoS_Context->maxEntryLimit += cur->maxEntryLimit;
        FlowQoS_Context->hwWatermarkPercent = cur->hwWatermarkPercent;
        FlowQoS_Context->hwCongested += cur->hwCongested;
        for (int i = 0; i < FlowQoS_Context->priorityQueueNum; i++)
        {
            FlowQoS_Context->weight[i] = cur->weight[i];
            FlowQoS_Context->total[i] += cur->total[i];
            FlowQoS_Context->finished[i] += cur->finished[i];
            FlowQoS_Context->onList[i] += cur->onList[i];
        }
        break;
    case 3: // Print Main Core Info
        cur = FlowQoS_Context;
        cmdline_printf(cl, "************************************Flow_QoS Info************************************\n");
        cmdline_printf(cl, "HWEntryLimit:%d AvailTokens:%d Watermark:%d%% CongestedCores:%d\n", cur->maxEntryLimit, cur->maxEntry, cur->hwWatermarkPercent, cur->hwCongested);
        for (int i = 0; i < FlowQoS_Context->priorityQueueNum; i++)
        {
            cmdline_printf(cl, "Priority %d , Weight %d , TotalFlows:%lu , OffloadedFlows:%lu ,OnListFlows:%lu, Tokens %d\n", i, cur->weight[i], cur->total[i], cur->finished[i], cur->onList[i], cur->maxEntry);
        }
        cmdline_printf(cl, "************************************Flow_QoS Info************************************\n");
        break;
    }
}
/**
 * @brief slave core of printFlowQoS() API
 *
 * @param args
 */
void printFlowQoS_slave(void *args)
{
    struct FlowQoS_Stats *stats = (struct FlowQoS_Stats *)args;
    printFlowQoS(&(stats[rte_lcore_id()]), 0, NULL);
}
/**
 * @brief master core of printFlowQoS() API, revoke flowQoS_message_multiThread_do API() and wait slaves copy stats to specified memory
 *
 */
void printFlowQoS_master()
{
    struct FlowQoS_Stats stats[MAX_CORES] = {0};
    flowQoS_message_multiThread_do(printFlowQoS_slave, (void *)stats);
    printFlowQoS(NULL, 1, NULL);
    unsigned int lcore_id = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        printFlowQoS(&(stats[lcore_id]), 2, NULL);
    }
    printFlowQoS(&(stats[lcore_id]), 3, flowQoS_getCmd());
}

/**
 * @brief slave core count total offloaded flows
 *
 * @param args
 */
void getFlowQoSOffload_slave(void *args)
{
    uint64_t *offloadedFlows = args;
    offloadedFlows[rte_lcore_id()] = 0;
    if (FlowQoS_Context)
    {
        for (int i = 0; i < FlowQoS_Context->priorityQueueNum; i++)
        {
            offloadedFlows[rte_lcore_id()] += FlowQoS_Context->finished[i];
        }
        // DOCA_LOG_INFO("Core %d offload %lu flows", rte_lcore_id(), offloadedFlows[rte_lcore_id()]);
    }
}
/**
 * @brief master core summary offloaded flows of slaves
 *
 * @return uint64_t
 */
uint64_t getFlowQoSOffload()
{
    static uint64_t offloadedFlows[MAX_CORES] = {0};
    flowQoS_message_multiThread_do(getFlowQoSOffload_slave, (void *)offloadedFlows);
    uint64_t res = 0;
    unsigned int lcore_id = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        res += offloadedFlows[lcore_id];
    }
    return res;
}

int flowQoS_qos_init(int priorityQueueNum, int weight[], int maxEntry, int offloadSpeed)
{
    unsigned lcore_id;
    int tokens = 0;
    FlowQoS_Context = (struct FlowQoS_Stats *)rte_malloc(NULL, sizeof(struct FlowQoS_Stats), 0);
    memset(FlowQoS_Context, 0, sizeof(struct FlowQoS_Stats));
    FlowQoS_Context->priorityQueueNum = priorityQueueNum;
    FlowQoS_Context->maxEntry = maxEntry;
    FlowQoS_Context->maxEntryLimit = maxEntry;
    FlowQoS_Context->hwWatermarkPercent = FLOWQOS_HW_WATERMARK_PERCENT;
    FlowQoS_Context->hwCongested = 0;
    FlowQoS_Context->lastStmp = rte_rdtsc();
    FlowQoS_Context->gap = rte_get_tsc_hz() * (rte_lcore_count() - 1) / offloadSpeed;

    for (int i = 0; i < priorityQueueNum; i++)
    {
        TAILQ_INIT(&(FlowQoS_Context->buckets[i]));
        FlowQoS_Context->weight[i] = weight[i];
        tokens += weight[i];
    }
    // FlowQoS_Context->gap *= tokens; //should know not all kinds of traffic will distribute packets evenly to different priorities.

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        rte_eal_remote_launch(initFlowQoS_Context, (void *)FlowQoS_Context, lcore_id);
        rte_eal_wait_lcore(lcore_id);
    }
    register_general_processor(flowQoS_do_entry_event, "QoS");
    DOCA_LOG_INFO("register flowQoS_do_entry_event");
    registerFlowQoSCmd();

    return 0;
}

/**********************************************************/

/**
 * @brief cmds of flowQoS module registered into dpdk cmdlines
 *
 */
struct cmd_dumpFlowQoS
{
    cmdline_fixed_string_t cmd;
};

static void cmd_dumpFlowQoS_parsed(__rte_unused void *parsed_result,
                                   struct cmdline *cl,
                                   __rte_unused void *data)
{
    // struct cmd_dumpFlowQoS *res = parsed_result;
    printFlowQoS_master();
}

cmdline_parse_token_string_t cmd_dumpFlowQoS_cmd =
    TOKEN_STRING_INITIALIZER(struct cmd_dumpFlowQoS, cmd, "dumpFlowQoS");

cmdline_parse_inst_t cmd_dumpFlowQoS_obj = {
    .f = cmd_dumpFlowQoS_parsed, /* function to call */
    .data = NULL,                /* 2nd arg of func */
    .help_str = "print FlowQoS Scheduler Info",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&cmd_dumpFlowQoS_cmd,
        NULL,
    },
};

void registerFlowQoSCmd()
{
    static bool cmdRegistered = false;
    if (!cmdRegistered)
    {
        flowQoS_registCmd(&cmd_dumpFlowQoS_obj);
        cmdRegistered = true;
        DOCA_LOG_INFO("Register dumpFlowQoS cmd");
    }
}
