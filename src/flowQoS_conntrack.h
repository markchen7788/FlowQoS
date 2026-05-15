/**
 * @file flowQoS_conntrack.h
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief L4-conntrack module for flowQoS, only tracking single direction and not tracking tcp 11 states
 * @version 0.1
 * @date 2024-01-13
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef FLOWQOS_CONNTRACK_H_
#define FLOWQOS_CONNTRACK_H_
#include "flowQoS_pipe.h"
#include "flowQoS_worker.h"
#include "flowQoS_env.h"

/**
 * @brief the type of function handling new flows
 *
 */
typedef packet_action (*flowQoS_newConn_handler)(struct FlowQoS_ENTRY *newEntry);
/**
 * @brief the type of function handling aged flows
 *
 */
typedef void (*flowQoS_agingConn_handler)(struct FlowQoS_ENTRY *newEntry);

/**
 * @brief init enviroment of L4-conntrack including mempool, hashTable and flowQoS module. Conns(TCP or UDP) from different ports will be stored in same hashTable and mempool
 *
 * @param maxConntrack the capacity of mempool
 * @param maxOffloadedEntry the maximum offloaded entry per core
 * @param offloadTime the interval between the first packet comming and the entry being offloaded. If fct of a flow smaller than this interval, this flow won't be offloaded. You can take it as filter to classify big flows
 * @param offloadSpeed the maximum speed of offloading doca-flow entry, currently it is not very accurate.
 * @return int
 */
int flowQoS_conntrack_init_env(int maxConntrack, int maxOffloadedEntry, int offloadTime, int offloadSpeed);
/**
 * @brief tune ConnSched-Filter thresholds at runtime.
 *
 * @param timeThresholdUs Tth in us, pass negative value to keep current value
 * @param packetThreshold Pth, pass negative value to keep current value
 * @param deltaTimeUs delta_t in us, pass negative value to keep current value
 * @param maxOffloadSpeed DPU max offload rate V in conn/s, pass negative value to keep current value
 * @return int
 */
int flowQoS_conntrack_tune_filter(int timeThresholdUs, int packetThreshold, int deltaTimeUs, int maxOffloadSpeed);
/**
 * @brief build doca-flow pipe for port. In some cases, we don't need to track upstream or downstream connection at the same time, so user can init one port for only tracking connections from single direction.
 *
 * @param port_id
 * @param maxOffloadedEntry the maximum offloaded entry in doca-flow pipe
 * @param actionFlags
 * @return int
 */
int flowQoS_conntrack_init_port(int port_id, int maxOffloadedEntry, uint64_t actionFlags);
/**
 * @brief register function handling new conn
 *
 * @param newConn_handler
 * @return int
 */
int flowQoS_regist_newConn_handler(flowQoS_newConn_handler newConn_handler);
/**
 * @brief register function handling aged conn
 * 
 * @param _agingConn_handler 
 * @return int 
 */
int flowQoS_regist_agingConn_handler(flowQoS_agingConn_handler _agingConn_handler);

#endif /* FLOWQOS_CONNTRACK_H_ */
