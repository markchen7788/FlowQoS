/**
 * @file flowQoS_router.h
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief simple arp module and router module
 * @version 0.1
 * @date 2024-01-21
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef FLOWQOS_ROUTER_H_
#define FLOWQOS_ROUTER_H_
#include "flowQoS_worker.h"
#include "flowQoS_cmd.h"
#include "flowQoS_env.h"
/**
 * @brief print port info to dpdk cmdline, which is similar to ifconfig
 *
 * @param cl
 */
void flowQoS_router_dumpPortInfo(struct cmdline *cl);
/**
 * @brief set mac of port
 *
 * @param port_id
 * @param mac
 */
void flowQoS_router_setPortMac(uint32_t port_id, uint8_t mac[6]);
/**
 * @brief get mac of port
 *
 * @param port_id
 * @param mac
 */
void flowQoS_router_getPortMac(uint32_t port_id, uint8_t mac[6]);
/**
 * @brief set ip of port like ifconfig
 *
 * @param name dpdk0 is port 0, dpdk1 is port 1
 * @param ip
 * @param prefix
 * @return int
 */
int flowQoS_router_ifconfig(char *name, uint32_t ip, int prefix);
/**
 * @brief if tip is local ip
 * 
 * @param tip 
 * @return int port id
 */
int flowQoS_router_isLocalIP(uint32_t tip);
/**
 * @brief return name of port 
 * 
 * @param port_id 
 * @param name 
 * @return int 
 */
int flowQoS_router_getLocalName(uint32_t port_id, char *name);
/**
 * @brief return ip of port
 * 
 * @param port_id 
 * @return uint32_t 
 */
uint32_t flowQoS_router_getLocalIP(uint32_t port_id);

/**
 * @brief init arp table
 * 
 * @param port_id 
 * @param postfix_len it decides the capacity of arp table
 * @return int 
 */
int flowQoS_router_initARP_Table(int port_id, int postfix_len);
/**
 * @brief set mac of ip
 * 
 * @param port_id 
 * @param ip 
 * @param mac 
 * @return int 
 */
int flowQoS_router_put_arp(int port_id, uint32_t ip, uint8_t mac[6]);
/**
 * @brief del mac of ip
 * 
 * @param port_id 
 * @param ip 
 * @param mac 
 * @return int 
 */
int flowQoS_router_del_arp(int port_id, uint32_t ip, uint8_t mac[6]);
/**
 * @brief get mac of ip
 * 
 * @param port_id 
 * @param ip 
 * @param mac 
 * @return int 
 */
int flowQoS_router_get_arp(int port_id, uint32_t ip, uint8_t mac[6]);
/**
 * @brief  dump arp table
 * 
 * @param cl 
 */
void flowQoS_router_dumpARP(struct cmdline *cl);

/**
 * @brief init route table
 * 
 * @return int 
 */
int flowQoS_router_initRoutingTable();
/**
 * @brief find gateway ip of this network
 * 
 * @param ip 
 * @param port_id 
 * @param gw_ip 
 * @return int 
 */
int flowQoS_router_findRoute(uint32_t ip, uint32_t *port_id, uint32_t *gw_ip);
/**
 * @brief add gateway ip of this network
 * 
 * @param ip 
 * @param prefix 
 * @param gw_ip 
 * @return int 
 */
int flowQoS_router_addRoute(uint32_t ip, uint32_t prefix, uint32_t gw_ip);
/**
 * @brief 
 * 
 * @param ip del gateway ip of this network
 * @param prefix 
 * @return int 
 */
int flowQoS_router_delRoute(uint32_t ip, uint32_t prefix);
/**
 * @brief dump route table
 * 
 * @param cl 
 * @return int 
 */
int flowQoS_router_dumpRoute(struct cmdline *cl);

/**
 * @brief enable this module
 * 
 * @param needCmdline if need cmdline to help interact with this module
 */
void registRoutingModule(bool needCmdline);
/**
 * @brief built-in function processing icmp and arp, it only receives icmp and arp packets passively.
 * 
 * @param m 
 * @return packet_action 
 */
packet_action flowQoS_ARP_ICMP_PROCESS(struct rte_mbuf *m);
#endif /* FLOWQOS_ROUTER_H_ */