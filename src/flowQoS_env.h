/**
 * @file flowQoS_env.h
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief build up doca-flow and dpdk env
 * @version 0.1
 * @date 2024-01-19
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef FLOWQOS_ENV_H_
#define FLOWQOS_ENV_H_
#include <string.h>
#include <rte_byteorder.h>
#include <doca_log.h>
#include <doca_argp.h>
#include <dpdk_utils.h>
#include <doca_flow.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include "flowQoS_message.h"
#define NB_PORTS 2///< num of doca-flow ports
extern struct doca_flow_port *ports[NB_PORTS];///< doca-flow ports
extern struct application_dpdk_config dpdk_config;///< dpdk config
/**
 * @brief init doca-flow and dpdk env
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int flowQoS_env_init(int argc, char **argv);
/**
 * @brief release doca-flow and dpdk resources
 * 
 */
void flowQoS_env_destroy();
#endif /* FLOWQOS_ENV_H_ */