/**
 * @file flowQoS_worker.h
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief slave workers module handling registered abstract tasks including sending and receving rte_mbuf, which is inspired by dpvs
 * @version 0.1
 * @date 2024-01-22
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef FLOWQOS_WORKER_H_
#define FLOWQOS_WORKER_H_
#include <rte_ethdev.h>

#define MAX_ETHPORTS 2
#define MAX_CORES 8
#define MAX_PROCESSOR_NUM 30 ///< maximum amout of abstract tasks[callback pointers]
#define PACKET_BURST 128
#define MAX_PKT_BURST PACKET_BURST
#define MAX_QUEUES MAX_CORES

#define DROP_PACKETS -1                                       ///< retured value from packet_processor, means drop this packet
#define IGNORE_PACKETS -2                                     ///< retured value from packet_processor, means doing nothing
typedef int packet_action;                                    ///< retured value from packet_processor, can be port_id[>=0,means redirect to this port], DROP_PACKETS or IGNORE_PACKETS
typedef packet_action (*packet_processor)(struct rte_mbuf *); ///< abstract task which procssing rte_mbuf
typedef int (*general_processor)(int);                        ///< general abstract task, returning positive value means the spent cpu cycles of this turn will be accumulated so that we can calculate the cpu consumption of this task  
/**
 * @brief lauch all slave workers
 *
 */
void launch_worker();
/**
 * @brief stop all slave workers
 *
 */
void stop_worker();
/**
 * @brief output slave workers stats
 *
 */
void dumpWorkerStats();
/**
 * @brief if slave workers are running
 *
 * @return true
 * @return false
 */
bool is_worker_running();
/**
 * @brief get the doca-flow queue id of this slave
 *
 * @param cid
 * @return int
 */
int getFlowQid(int cid);
/**
 * @brief register a task procssing packet
 * 
 * @param p 
 * @return int 
 */
int register_packet_processor(packet_processor p);
/**
 * @brief register a general task
 * 
 * @param p 
 * @param general_processor_name 
 * @return int 
 */
int register_general_processor(general_processor p, char *general_processor_name);

#endif /* FLOWQOS_WORKER_H_ */