/**
 * @file flowQoS_qos.h
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief  QoS-based scheduler for adding doca-flow entries into FDB 
 * @version 0.1
 * @date 2024-01-26
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef FLOWQOS_QOS_H_
#define FLOWQOS_QOS_H_
#include "flowQoS_cmd.h"
#include "flowQoS_pipe.h"
#include "flowQoS_worker.h"

#define MAXPriorityQueueNum 8 ///< maximum amount of priorities
#define FLOWQOS_HW_WATERMARK_PERCENT 80 ///< default high-watermark of hardware table utilization

typedef void (*FlowQoS_QoS_Congestion_Handler)(uint64_t occupied, uint64_t maxEntry, void *args);

/**
 * @brief FlowQoS_ENTRY priority queue head
 *
 */
TAILQ_HEAD(FlowQoS_ENTRY_Bucket, FlowQoS_ENTRY);
/**
 * @brief flowQoS context, each core has its own context
 *
 */
struct FlowQoS_Stats
{
    int priorityQueueNum;                                     ///< amount of priorities
    int weight[MAXPriorityQueueNum];                          ///< weight of priority queue
    int maxEntry;                                             ///< maximum amount of doca-flow entries can be offloaded per-core
    int maxEntryLimit;                                        ///< hardware entry budget per-core
    int hwWatermarkPercent;                                   ///< high-watermark of hardware table utilization
    int hwCongested;                                          ///< whether hardware table is currently above high-watermark
    uint64_t total[MAXPriorityQueueNum];                      ///< total flows added to this priority queue
    uint64_t finished[MAXPriorityQueueNum];                   ///< total offloaded flows from this priority queue
    uint64_t onList[MAXPriorityQueueNum];                     ///< total active onload flows from this priority queue
    uint64_t gap;                                             ///< interval of flowQoS module processing priority queues
    uint64_t lastStmp;                                        ///< last timestamp when flowQoS module processing priority queues
    struct FlowQoS_ENTRY_Bucket buckets[MAXPriorityQueueNum]; ///< FlowQoS_ENTRY priority queue head
};
/**
 * @brief init flowQoS module
 *
 * @param priorityQueueNum
 * @param weight
 * @param maxEntry maximum amount of doca-flow entries can be offloaded per-core
 * @param offloadSpeed interval of flowQoS module processing priority queues
 * @return int
 */
int flowQoS_qos_init(int priorityQueueNum, int weight[], int maxEntry, int offloadSpeed);
/**
 * @brief register callback invoked when QoS observes hardware table high-watermark pressure
 *
 * @param handler
 * @param args
 */
void flowQoS_regist_congestion_handler(FlowQoS_QoS_Congestion_Handler handler, void *args);
/**
 * @brief add flowQoS_entry to priority queue
 *
 * @param entry
 * @param priority
 */
void flowQoS_add_entry_event(struct FlowQoS_ENTRY *entry, int priority);
/**
 * @brief del flowQoS_entry from priority queue
 *
 * @param entry
 */
void flowQoS_del_entry_event(struct FlowQoS_ENTRY *entry);
/**
 * @brief revoked after flow aged from doca-flow FDB so that FlowQoS_Stats->maxEntry will increase by 1
 *
 */
void flowQoS_return_entry_event();
/**
 * @brief get the amount of flows offloaded by flowQoS module
 *
 * @return uint64_t
 */
uint64_t getFlowQoSOffload();

#endif /* FLOWQOS_QOS_H_ */
