/**
 * @file flowQoS_cmd.h
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief cmdline module built by dpdk cmdline
 * @version 0.1
 * @date 2024-01-11
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef FLOWQOS_CMD_H_
#define FLOWQOS_CMD_H_
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline.h>
#include <rte_string_fns.h>
#include <cmdline_socket.h>
#include <rte_byteorder.h>
#include <cmdline_parse_etheraddr.h>

/**
 * @brief return cmdline pointer of dpdk cmdline so that other module can print info into cmdline 
 * 
 * @return struct cmdline* 
 */
struct cmdline *flowQoS_getCmd();
/**
 * @brief register a cmd onto dpdk cmdline, other module or user can revoke this to add defined cmd into dpdk cmdline  
 * 
 * @param ctx defined cmdline object
 * @return int 
 */
int flowQoS_registCmd(cmdline_parse_inst_t *ctx);
/**
 * @brief enter into dpdk cmdline
 * 
 */
void flowQoS_cmd();
#endif /* FLOWQOS_CMD_H_ */
