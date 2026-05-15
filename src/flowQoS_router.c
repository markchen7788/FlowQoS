/**
 * @file flowQoS_router.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief simple arp module and router module
 * @version 0.1
 * @date 2024-01-21
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_rwlock.h>
#include <stdint.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_icmp.h>
#include <rte_arp.h>
#include "flowQoS_router.h"
DOCA_LOG_REGISTER(FLOWQOS_ROUTER);

static const int port_num = NB_PORTS; ///< port num
struct ARP_Entry
{
    uint32_t ip;
    uint8_t mac[6];
};
struct ARP_Table
{
    uint32_t port_id;
    uint32_t MaxEntry;
    uint32_t Mask;
    struct ARP_Entry *arps;
    rte_rwlock_t lock; ///< use rw_lock to synchronize cause most of operations is reading
} arp_tables[MAX_ETHPORTS] = {0};

/**
 * @brief output of ifconfig
 *
 */
struct LocalPortInfo
{
    char name[16];
    uint32_t ip;
    uint32_t prefix;
    uint8_t mac[6];
    uint16_t mtu;
    struct rte_eth_link link; ///< get dpdk port speed
    uint16_t txqueuelen;
    struct rte_eth_stats stats; ///< get rx and tx info by using dpdk rte_eth_stats_get() api
} localPortInfo[MAX_ETHPORTS] = {0};

#define IPV4_L3FWD_LPM_MAX_RULES 256 ///< maximum capacity of routing table
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)
struct RoutingTable
{
    struct rte_lpm *lpm; ///< store the index[id] of route, real route is "routingTable.ip[id]/routingTable.prefix[id] via routingTable.gw_ip[id] dev routingTable.port_id[id]"
    uint32_t ip[IPV4_L3FWD_LPM_MAX_RULES];
    uint32_t prefix[IPV4_L3FWD_LPM_MAX_RULES];
    uint32_t gw_ip[IPV4_L3FWD_LPM_MAX_RULES];
    uint32_t port_id[IPV4_L3FWD_LPM_MAX_RULES];
    rte_rwlock_t lock; ///< use rw_lock to synchronize cause most of operations is reading
} routingTable = {0};

/***portInfo Module******************************************************************************************************************/

/**
 * @brief init port info by id
 *
 * @param port_id
 */
void initLocalPortInfo(int port_id)
{
    sprintf(localPortInfo[port_id].name, "dpdk%d", port_id);
    rte_eth_dev_get_mtu(port_id, &(localPortInfo[port_id].mtu));
    struct rte_eth_txq_info info = {0};
    rte_eth_tx_queue_info_get(port_id, 0, &info);
    localPortInfo[port_id].txqueuelen = info.nb_desc;
    struct rte_ether_addr l2fwd_ports_eth_addr = {0};
    rte_eth_macaddr_get(port_id, &l2fwd_ports_eth_addr);
    rte_memcpy(localPortInfo[port_id].mac, l2fwd_ports_eth_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
}

void flowQoS_router_getPortMac(uint32_t port_id, uint8_t mac[6])
{
    rte_memcpy(mac, localPortInfo[port_id].mac, RTE_ETHER_ADDR_LEN);
}

void flowQoS_router_setPortMac(uint32_t port_id, uint8_t mac[6])
{
    rte_memcpy(localPortInfo[port_id].mac, mac, RTE_ETHER_ADDR_LEN);
}

/**
 * @brief convert the unit of bytes
 *
 * @param byts
 * @return char*
 */
char *getBytes(uint64_t byts)
{
    char *unit[7] = {"B", "KB", "MB", "GB", "TB", "PB", "EB"};
    static char str[30] = {0};
    double res = byts;
    int i = 0;
    for (i = 0; i < 7; i++)
    {
        if (res < 1024)
        {
            sprintf(str, "%.1f %s", res, unit[i]);
            return str;
        }
        res = res / 1024;
    }
    sprintf(str, "%.1f %s", res, unit[i - 1]);
    return str;
}

/**
 * @brief output local port info to dpdk cmdline
 *
 * @param cl
 * @param port_id
 */
void printLocalPortInfo(struct cmdline *cl, int port_id)
{
    rte_eth_link_get(port_id, &(localPortInfo[port_id].link));
    rte_eth_stats_get(port_id, &(localPortInfo[port_id].stats));
    cmdline_printf(cl, "%s: flags=4163<%sBROADCAST,%sMULTICAST> mtu %d\n", localPortInfo[port_id].name, localPortInfo[port_id].link.link_status == ETH_LINK_UP ? "UP," : "DOWN,", is_worker_running() ? "RUNNING," : "", localPortInfo[port_id].mtu);
    if (localPortInfo[port_id].ip != 0)
    {
        uint32_t tip = localPortInfo[port_id].ip, prefix = localPortInfo[port_id].prefix, mip = ~((1 << (32 - prefix)) - 1), bip = tip | ((1 << (32 - prefix)) - 1);
        cmdline_printf(cl, "        inet %d.%d.%d.%d  netmask %d.%d.%d.%d  broadcast %d.%d.%d.%d\n",
                       (tip & 0xff000000) >> 24,
                       (tip & 0x00ff0000) >> 16,
                       (tip & 0x0000ff00) >> 8,
                       (tip & 0x000000ff),
                       (mip & 0xff000000) >> 24,
                       (mip & 0x00ff0000) >> 16,
                       (mip & 0x0000ff00) >> 8,
                       (mip & 0x000000ff),
                       (bip & 0xff000000) >> 24,
                       (bip & 0x00ff0000) >> 16,
                       (bip & 0x0000ff00) >> 8,
                       (bip & 0x000000ff));
    }
    cmdline_printf(cl, "        ether %02x:%02x:%02x:%02x:%02x:%02x  txqueuelen %d  (Ethernet %uGbE)\n",
                   localPortInfo[port_id].mac[0],
                   localPortInfo[port_id].mac[1],
                   localPortInfo[port_id].mac[2],
                   localPortInfo[port_id].mac[3],
                   localPortInfo[port_id].mac[4],
                   localPortInfo[port_id].mac[5],
                   localPortInfo[port_id].txqueuelen,
                   localPortInfo[port_id].link.link_speed / 1000);
    cmdline_printf(cl, "        RX packets %lu bytes %lu (%s)\n", localPortInfo[port_id].stats.ipackets, localPortInfo[port_id].stats.ibytes, getBytes(localPortInfo[port_id].stats.ibytes));
    cmdline_printf(cl, "        RX errors %lu dropped %lu burst %d\n", localPortInfo[port_id].stats.ierrors, localPortInfo[port_id].stats.imissed, MAX_PKT_BURST);
    cmdline_printf(cl, "        TX packets %lu bytes %lu (%s)\n", localPortInfo[port_id].stats.opackets, localPortInfo[port_id].stats.obytes, getBytes(localPortInfo[port_id].stats.obytes));
    cmdline_printf(cl, "        TX errors %lu dropped %u burst %d\n", localPortInfo[port_id].stats.oerrors, 0 /*Reserved*/, MAX_PKT_BURST);
    cmdline_printf(cl, "\n");
}

int flowQoS_router_ifconfig(char *name, uint32_t ip, int prefix)
{
    for (int port_id = 0; port_id < port_num; port_id++)
    {
        if (strcmp(localPortInfo[port_id].name, name) == 0)
        {
            if (localPortInfo[port_id].ip != 0)
            {
                flowQoS_router_delRoute(localPortInfo[port_id].ip, localPortInfo[port_id].prefix);
            }
            localPortInfo[port_id].ip = ip;
            localPortInfo[port_id].prefix = prefix;
            flowQoS_router_initARP_Table(port_id, 32 - prefix);
            flowQoS_router_addRoute(ip, prefix, 0);
            return 1;
        }
    }
    cmdline_printf(flowQoS_getCmd(), "Cannot find port\n");
    return 0;
}

void flowQoS_router_dumpPortInfo(struct cmdline *cl)
{
    for (int i = 0; i < port_num; i++)
    {
        printLocalPortInfo(cl, i);
    }
}

int flowQoS_router_getLocalName(uint32_t port_id, char *name)
{
    int ret = port_id >= 0 && port_id < port_num;
    if (ret)
    {
        sprintf(name, "%s", localPortInfo[port_id].name);
    }
    return ret;
}

uint32_t flowQoS_router_getLocalIP(uint32_t port_id)
{
    return localPortInfo[port_id].ip;
}

int flowQoS_router_isLocalIP(uint32_t tip)
{
    for (int i = 0; i < port_num; i++)
    {
        uint32_t mask = ~((1 << (32 - localPortInfo[i].prefix)) - 1);
        if ((tip & mask) == (localPortInfo[i].ip & mask))
        {
            return i;
        }
    }
    return -1;
}

/***ARP Module******************************************************************************************************************/

int flowQoS_router_initARP_Table(int port_id, int postfix_len) // write lock
{
    rte_rwlock_write_lock(&(arp_tables[port_id].lock));
    /*--------------write lock-------------------*/
    if (arp_tables[port_id].arps != NULL)
    {
        DOCA_LOG_INFO("Free ARP Table Success");
        rte_free(arp_tables[port_id].arps);
    }
    arp_tables[port_id].port_id = port_id;
    arp_tables[port_id].MaxEntry = 1 << postfix_len;
    arp_tables[port_id].Mask = (1 << postfix_len) - 1;
    arp_tables[port_id].arps = (struct ARP_Entry *)rte_malloc(NULL, sizeof(struct ARP_Entry) * arp_tables[port_id].MaxEntry, 0);
    if (arp_tables[port_id].arps == NULL)
    {
        DOCA_LOG_INFO("Unable to create the ARP table");
        goto ERR;
    }
    memset(arp_tables[port_id].arps, 0, sizeof(struct ARP_Entry) * arp_tables[port_id].MaxEntry);
    DOCA_LOG_INFO("Init ARP Table Success");
    goto OK;

    /*--------------write unlock-------------------*/
OK:
    rte_rwlock_write_unlock(&(arp_tables[port_id].lock));
    return 1;
ERR:
    rte_rwlock_write_unlock(&(arp_tables[port_id].lock));
    return 0;
}

int flowQoS_router_put_arp(int port_id, uint32_t ip, uint8_t mac[6])
{
    rte_rwlock_write_lock(&(arp_tables[port_id].lock));
    /*--------------write lock-------------------*/
    if (arp_tables[port_id].arps == NULL)
        goto ERR;
    int pos = ip & arp_tables[port_id].Mask;
    arp_tables[port_id].arps[pos].ip = ip;
    for (int i = 0; i < 6; i++)
        arp_tables[port_id].arps[pos].mac[i] = mac[i];
    goto OK;
    /*--------------write unlock-------------------*/
OK:
    rte_rwlock_write_unlock(&(arp_tables[port_id].lock));
    return 1;
ERR:
    rte_rwlock_write_unlock(&(arp_tables[port_id].lock));
    return 0;
}
int flowQoS_router_del_arp(int port_id, uint32_t ip, uint8_t mac[6])
{
    rte_rwlock_write_lock(&(arp_tables[port_id].lock));
    /*--------------write lock-------------------*/
    if (arp_tables[port_id].arps == NULL)
        goto ERR;
    int pos = ip & arp_tables[port_id].Mask;
    arp_tables[port_id].arps[pos].ip = 0;
    for (int i = 0; i < 6; i++)
        arp_tables[port_id].arps[pos].mac[i] = 0;
    goto OK;
    /*--------------write unlock-------------------*/
OK:
    rte_rwlock_write_unlock(&(arp_tables[port_id].lock));
    return 1;
ERR:
    rte_rwlock_write_unlock(&(arp_tables[port_id].lock));
    return 0;
}
int flowQoS_router_get_arp(int port_id, uint32_t ip, uint8_t mac[6])
{
    rte_rwlock_read_lock(&(arp_tables[port_id].lock));
    /*--------------read lock-------------------*/
    if (arp_tables[port_id].arps == NULL)
        goto ERR;
    int pos = ip & arp_tables[port_id].Mask;
    if (arp_tables[port_id].arps[pos].ip == 0)
        goto ERR;
    for (int i = 0; i < 6; i++)
        mac[i] = arp_tables[port_id].arps[pos].mac[i];
    goto OK;
    /*--------------read unlock-------------------*/
OK:
    rte_rwlock_read_unlock(&(arp_tables[port_id].lock));
    return 1;
ERR:
    rte_rwlock_read_unlock(&(arp_tables[port_id].lock));
    return 0;
}
/**
 * @brief output arp entry to dpdk cmdline
 *
 * @param cl
 * @param ip
 * @param mac
 * @param port_id
 */
void printARP(struct cmdline *cl, uint32_t ip, uint8_t mac[6], int port_id)
{
    char ipstr[20] = {0};
    sprintf(ipstr, "%d.%d.%d.%d",
            (ip & 0xff000000) >> 24,
            (ip & 0x00ff0000) >> 16,
            (ip & 0x0000ff00) >> 8,
            (ip & 0x000000ff));
    cmdline_printf(cl, "%-20s%02x:%02x:%02x:%02x:%02x:%02x     %s\n", ipstr, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], localPortInfo[port_id].name);
}
void flowQoS_router_dumpARP(struct cmdline *cl)
{
    cmdline_printf(cl, "%-20s%-22s%s\n", "Address", "HWaddress", "Iface");
    for (int i = 0; i < MAX_ETHPORTS; i++)
    {
        rte_rwlock_read_lock(&(arp_tables[i].lock));
        /*--------------read lock-------------------*/
        if (arp_tables[i].arps != NULL)
        {
            for (int j = 0; j < arp_tables[i].MaxEntry; j++)
            {
                if (arp_tables[i].arps[j].ip == 0)
                    continue;
                printARP(cl, arp_tables[i].arps[j].ip, arp_tables[i].arps[j].mac, arp_tables[i].port_id);
            }
        }
        /*--------------read unlock-------------------*/
        rte_rwlock_read_unlock(&(arp_tables[i].lock));
    }
}

/***Routing Module******************************************************************************************************************/
int flowQoS_router_initRoutingTable()
{

    struct rte_lpm_config config_ipv4;
    /* create the LPM table */
    config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
    config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
    config_ipv4.flags = 0;
    if (routingTable.lpm)
    {
        DOCA_LOG_INFO("The LPM table has existed");
        return 0;
    }
    routingTable.lpm = rte_lpm_create("LPM", rte_socket_id(), &config_ipv4);
    if (routingTable.lpm == NULL)
    {
        DOCA_LOG_INFO("Unable to create the LPM table");
        return 0;
    }
    rte_rwlock_init(&(routingTable.lock));
    DOCA_LOG_INFO("Init LPM Success");
    return 1;
}
int flowQoS_router_findRoute(uint32_t ip, uint32_t *port_id, uint32_t *gw_ip)
{
    uint32_t pos = 0;

    rte_rwlock_read_lock(&(routingTable.lock));
    /*--------------read lock-------------------*/
    int ret = rte_lpm_lookup(routingTable.lpm, ip, &pos) == 0 ? 1 : 0;
    if (ret == 0)
        ret = rte_lpm_lookup(routingTable.lpm, 0, &pos) == 0 ? 1 : 0; // find default route
    *gw_ip = routingTable.gw_ip[pos];
    *port_id = routingTable.port_id[pos];
    /*--------------read unlock-------------------*/
    rte_rwlock_read_unlock(&(routingTable.lock));
    return ret;
}
/**
 * @brief if this position stores a route
 *
 * @param pos
 * @return int
 */
int isRoute(int pos)
{
    return routingTable.port_id[pos] + routingTable.gw_ip[pos] + routingTable.ip[pos] + routingTable.prefix[pos];
}
int flowQoS_router_addRoute(uint32_t ip, uint32_t prefix, uint32_t gw_ip)
{
    rte_rwlock_write_lock(&(routingTable.lock));
    /*--------------write lock-------------------*/
    int pos = -1;
    uint32_t mask = ~((1 << (32 - prefix)) - 1);
    ip = ip & mask;
    for (int i = 0; i < IPV4_L3FWD_LPM_MAX_RULES; i++)
    {
        if (isRoute(i)) // if this pos has a route
        {
            if (ip == routingTable.ip[i])
            {
                DOCA_LOG_INFO("Route Exists");
                goto ERR;
            }
        }
        else
        {
            pos = i;
        }
    }
    if (pos == -1)
    {
        DOCA_LOG_INFO("Routing Table Is full");
        goto ERR;
    }

    int ret = rte_lpm_add(routingTable.lpm, ip, prefix, pos);
    int port = -1;
    if (ret == 0)
    {
        if (gw_ip == 0)
        {
            port = flowQoS_router_isLocalIP(ip); // handle local route
        }
        else
        {
            port = flowQoS_router_isLocalIP(gw_ip); // handle remote route
        }
        if (port == -1)
        {
            DOCA_LOG_INFO("Route Add Fail cause gw is not local IP");
            goto ERR;
        }
        routingTable.ip[pos] = ip & mask;
        routingTable.prefix[pos] = prefix;
        routingTable.gw_ip[pos] = gw_ip;
        routingTable.port_id[pos] = port;
        DOCA_LOG_INFO("Add a Route:%d.%d.%d.%d/%u==>%d.%d.%d.%d at pos %d",
                      (ip & 0xff000000) >> 24,
                      (ip & 0x00ff0000) >> 16,
                      (ip & 0x0000ff00) >> 8,
                      (ip & 0x000000ff), prefix,
                      (gw_ip & 0xff000000) >> 24,
                      (gw_ip & 0x00ff0000) >> 16,
                      (gw_ip & 0x0000ff00) >> 8,
                      (gw_ip & 0x000000ff), pos);
        goto OK;
    }
    else
    {
        DOCA_LOG_INFO("LPM Insert Fail");
        goto ERR;
    }

    /*--------------write unlock-------------------*/
ERR:
    rte_rwlock_write_unlock(&(routingTable.lock));
    return 0;
OK:
    rte_rwlock_write_unlock(&(routingTable.lock));
    return 1;
}
int flowQoS_router_delRoute(uint32_t ip, uint32_t prefix)
{
    rte_rwlock_write_lock(&(routingTable.lock));
    /*--------------write lock-------------------*/
    uint32_t mask = ~((1 << (32 - prefix)) - 1);
    ip = ip & mask;
    for (int i = 0; i < IPV4_L3FWD_LPM_MAX_RULES; i++)
    {
        if (isRoute(i) && ip == routingTable.ip[i])
        {
            uint32_t gw_ip = 0, port_id = 0;
            flowQoS_router_findRoute(routingTable.ip[i], &port_id, &gw_ip);
            int ret = rte_lpm_delete(routingTable.lpm, ip, prefix);
            if (ret == 0)
            {
                routingTable.ip[i] = 0;
                routingTable.prefix[i] = 0;
                routingTable.gw_ip[i] = 0;
                routingTable.port_id[i] = 0;

                DOCA_LOG_INFO("Del a Route:%d.%d.%d.%d/%u==>%d.%d.%d.%d on %s",
                              (ip & 0xff000000) >> 24,
                              (ip & 0x00ff0000) >> 16,
                              (ip & 0x0000ff00) >> 8,
                              (ip & 0x000000ff), prefix,
                              (gw_ip & 0xff000000) >> 24,
                              (gw_ip & 0x00ff0000) >> 16,
                              (gw_ip & 0x0000ff00) >> 8,
                              (gw_ip & 0x000000ff), localPortInfo[port_id].name);
                goto OK;
            }
            DOCA_LOG_INFO("LPM Del Fail");
        }
    }
    DOCA_LOG_INFO("Route Del Fail");
    goto ERR;
    /*--------------write unlock-------------------*/
ERR:
    rte_rwlock_write_unlock(&(routingTable.lock));
    return 0;
OK:
    rte_rwlock_write_unlock(&(routingTable.lock));
    return 1;
}

int flowQoS_router_dumpRoute(struct cmdline *cl) // Destination     Gateway         Genmask         Use Iface
{
    rte_rwlock_read_lock(&(routingTable.lock));
    /*--------------read lock-------------------*/
    cmdline_printf(cl, "%-20s%-20s%-20s%-20s\n", "Destination", "Gateway", "Genmask", "Iface");
    int ret = 0;
    for (int i = 0; i < IPV4_L3FWD_LPM_MAX_RULES; i++)
    {
        if (isRoute(i))
        {
            uint32_t ip = routingTable.ip[i], prefix = routingTable.prefix[i], gw_ip = 0, port_id = 0;
            uint32_t netmask = ~((1 << (32 - prefix)) - 1);
            if (flowQoS_router_findRoute(ip, &port_id, &gw_ip))
            {
                char s1[20], s2[20], s3[20];
                sprintf(s1, "%d.%d.%d.%d", (ip & 0xff000000) >> 24,
                        (ip & 0x00ff0000) >> 16,
                        (ip & 0x0000ff00) >> 8,
                        (ip & 0x000000ff));
                sprintf(s3, "%d.%d.%d.%d", (netmask & 0xff000000) >> 24,
                        (netmask & 0x00ff0000) >> 16,
                        (netmask & 0x0000ff00) >> 8,
                        (netmask & 0x000000ff));
                sprintf(s2, "%d.%d.%d.%d", (gw_ip & 0xff000000) >> 24,
                        (gw_ip & 0x00ff0000) >> 16,
                        (gw_ip & 0x0000ff00) >> 8,
                        (gw_ip & 0x000000ff));
                if (ip == 0) // handle default route
                    cmdline_printf(cl, "%-20s%-20s%-20s%-20s\n", "default", s2, "0.0.0.0", localPortInfo[port_id].name);
                else
                    cmdline_printf(cl, "%-20s%-20s%-20s%-20s\n", s1, s2, s3, localPortInfo[port_id].name);
                ret++;
            }
        }
    }
    /*--------------read unlock-------------------*/
    rte_rwlock_read_unlock(&(routingTable.lock));
    return ret;
}

/***cmdline Module******************************************************************************************************************/

/**
 * @brief ifconfig cmd of router module, eg: ifconfig dpdk0 192.168.200.2 netmask 255.255.255.0
 *
 */
struct ifconfig_cmd
{
    cmdline_fixed_string_t action;
    cmdline_fixed_string_t dev;
    cmdline_ipaddr_t ip;
    cmdline_fixed_string_t netmask;
    cmdline_ipaddr_t mask_ip;
};

static void ifconfig_cmd_parsed(__rte_unused void *parsed_result,
                                struct cmdline *cl,
                                __rte_unused void *data)
{
    struct ifconfig_cmd *res = parsed_result;
    if (res->ip.family == AF_INET && res->mask_ip.family == AF_INET)
    {
        uint32_t tip = rte_be_to_cpu_32(res->ip.addr.ipv4.s_addr), mask_ip = rte_be_to_cpu_32(res->mask_ip.addr.ipv4.s_addr), prefix = 0;
        for (int i = 0; i < 32; i++)
        {
            uint32_t mask = ~((1 << i) - 1);
            if (mask == mask_ip)
            {
                prefix = 32 - i;
            }
        }
        if (prefix == 0)
        {
            cmdline_printf(cl, "set prefix to default val 24");
            prefix = 24;
        }
        flowQoS_router_ifconfig(res->dev, tip, prefix);
    }
}

cmdline_parse_token_string_t ifconfig_cmd_action =
    TOKEN_STRING_INITIALIZER(struct ifconfig_cmd, action, "ifconfig");
cmdline_parse_token_string_t ifconfig_cmd_dev =
    TOKEN_STRING_INITIALIZER(struct ifconfig_cmd, dev, NULL);
cmdline_parse_token_ipaddr_t ifconfig_cmd_ip =
    TOKEN_IPADDR_INITIALIZER(struct ifconfig_cmd, ip);
cmdline_parse_token_string_t ifconfig_cmd_netmask =
    TOKEN_STRING_INITIALIZER(struct ifconfig_cmd, netmask, "netmask");
cmdline_parse_token_ipaddr_t ifconfig_cmd_mask_ip =
    TOKEN_IPADDR_INITIALIZER(struct ifconfig_cmd, mask_ip);

cmdline_parse_inst_t ifconfig_cmd_obj = {
    .f = ifconfig_cmd_parsed, /* function to call */
    .data = NULL,             /* 2nd arg of func */
    .help_str = "eg: ifconfig dpdk0 192.168.200.2 netmask 255.255.255.0",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&ifconfig_cmd_action,
        (void *)&ifconfig_cmd_dev,
        (void *)&ifconfig_cmd_ip,
        (void *)&ifconfig_cmd_netmask,
        (void *)&ifconfig_cmd_mask_ip,
        NULL,
    },
};
/**********************************************************/
/**
 * @brief arp cmd of router module, eg: arp -s 192.168.200.2 b8:ce:f6:d5:cc:5f
 *
 */
struct arp_cmd
{
    cmdline_fixed_string_t action;
    cmdline_fixed_string_t option;
    cmdline_ipaddr_t ip;
    cmdline_fixed_string_t mac;
};

static void arp_cmd_parsed(__rte_unused void *parsed_result,
                           struct cmdline *cl,
                           __rte_unused void *data)
{
    struct arp_cmd *res = parsed_result;
    if (res->ip.family == AF_INET)
    {
        uint32_t tip = rte_be_to_cpu_32(res->ip.addr.ipv4.s_addr);
        uint8_t peer_addr[6];
        cmdline_printf(cl, "mac:%s\n", res->mac);
        if (cmdline_parse_etheraddr(NULL, res->mac, &peer_addr, sizeof(peer_addr)) < 0)
        {
            cmdline_printf(cl, "Invalid ethernet address: %s\n", res->mac);
            return;
        }
        int port = flowQoS_router_isLocalIP(tip);
        if (port != -1)
        {
            if (strcmp(res->option, "-s") == 0)
                flowQoS_router_put_arp(port, tip, peer_addr);
            else
                flowQoS_router_del_arp(port, tip, peer_addr);
            return;
        }
    }
    cmdline_printf(cl, "Invalid IP addr\n");
}

cmdline_parse_token_string_t arp_cmd_action =
    TOKEN_STRING_INITIALIZER(struct arp_cmd, action, "arp");
cmdline_parse_token_string_t arp_cmd_option =
    TOKEN_STRING_INITIALIZER(struct arp_cmd, option, "-s#-d");
cmdline_parse_token_ipaddr_t arp_cmd_ip =
    TOKEN_IPADDR_INITIALIZER(struct arp_cmd, ip);
cmdline_parse_token_string_t arp_cmd_mac =
    TOKEN_STRING_INITIALIZER(struct arp_cmd, mac, NULL);

cmdline_parse_inst_t arp_cmd_obj = {
    .f = arp_cmd_parsed, /* function to call */
    .data = NULL,        /* 2nd arg of func */
    .help_str = "eg: arp -s 192.168.200.2 b8:ce:f6:d5:cc:5f",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&arp_cmd_action,
        (void *)&arp_cmd_option,
        (void *)&arp_cmd_ip,
        (void *)&arp_cmd_mac,
        NULL,
    },
};
/**********************************************************/
/**
 * @brief route cmd of router module, eg:route del -net 192.168.201.0 netmask 255.255.255.0 gw 192.168.200.2
 *
 */
struct route_cmd
{
    cmdline_fixed_string_t action;
    cmdline_fixed_string_t option;
    cmdline_fixed_string_t net;
    cmdline_ipaddr_t ip;
    cmdline_fixed_string_t netmask;
    cmdline_ipaddr_t mask_ip;
    cmdline_fixed_string_t gw;
    cmdline_ipaddr_t gw_ip;
};

static void route_cmd_parsed(__rte_unused void *parsed_result,
                             struct cmdline *cl,
                             __rte_unused void *data)
{
    struct route_cmd *res = parsed_result;
    if (res->ip.family == AF_INET && res->gw_ip.family == AF_INET)
    {
        uint32_t tip = rte_be_to_cpu_32(res->ip.addr.ipv4.s_addr), mask_ip = rte_be_to_cpu_32(res->mask_ip.addr.ipv4.s_addr), gw_ip = rte_be_to_cpu_32(res->gw_ip.addr.ipv4.s_addr), prefix = 0;
        for (int i = 0; i < 32; i++)
        {
            uint32_t mask = ~((1 << i) - 1);
            if (mask == mask_ip)
            {
                prefix = 32 - i;
            }
        }
        if (prefix == 0)
        {
            cmdline_printf(cl, "set prefix to default val 24");
            prefix = 24;
        }
        if (strcmp(res->option, "add") == 0)
            flowQoS_router_addRoute(tip, prefix, gw_ip);
        else
            flowQoS_router_delRoute(tip, prefix);
        return;
    }
    cmdline_printf(cl, "Not Support IPv6\n");
}

cmdline_parse_token_string_t route_cmd_action =
    TOKEN_STRING_INITIALIZER(struct route_cmd, action, "route");
cmdline_parse_token_string_t route_cmd_option =
    TOKEN_STRING_INITIALIZER(struct route_cmd, option, "add#del");
cmdline_parse_token_string_t route_cmd_net =
    TOKEN_STRING_INITIALIZER(struct route_cmd, net, "-net");
cmdline_parse_token_ipaddr_t route_cmd_ip =
    TOKEN_IPADDR_INITIALIZER(struct route_cmd, ip);
cmdline_parse_token_string_t route_cmd_netmask =
    TOKEN_STRING_INITIALIZER(struct route_cmd, netmask, "netmask");
cmdline_parse_token_ipaddr_t route_cmd_mask_ip =
    TOKEN_IPADDR_INITIALIZER(struct route_cmd, mask_ip);
cmdline_parse_token_string_t route_cmd_gw =
    TOKEN_STRING_INITIALIZER(struct route_cmd, gw, "gw");
cmdline_parse_token_ipaddr_t route_cmd_gw_ip =
    TOKEN_IPADDR_INITIALIZER(struct route_cmd, gw_ip);

cmdline_parse_inst_t route_cmd_obj = {
    .f = route_cmd_parsed, /* function to call */
    .data = NULL,          /* 2nd arg of func */
    .help_str = "eg: route del -net 192.168.201.0 netmask 255.255.255.0 gw 192.168.200.2",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&route_cmd_action,
        (void *)&route_cmd_option,
        (void *)&route_cmd_net,
        (void *)&route_cmd_ip,
        (void *)&route_cmd_netmask,
        (void *)&route_cmd_mask_ip,
        (void *)&route_cmd_gw,
        (void *)&route_cmd_gw_ip,
        NULL,
    },
};
/**********************************************************/ 
/**
 * @brief route gateway cmd of router module, eg: route add default gw 192.168.201.1
 *
 */
struct default_route_cmd
{
    cmdline_fixed_string_t action;
    cmdline_fixed_string_t option;
    cmdline_fixed_string_t _default;
    cmdline_fixed_string_t gw;
    cmdline_ipaddr_t gw_ip;
};

static void default_route_cmd_parsed(__rte_unused void *parsed_result,
                                     struct cmdline *cl,
                                     __rte_unused void *data)
{
    struct default_route_cmd *res = parsed_result;
    if (res->gw_ip.family == AF_INET)
    {
        uint32_t gw_ip = rte_be_to_cpu_32(res->gw_ip.addr.ipv4.s_addr);
        if (strcmp(res->option, "add") == 0)
            flowQoS_router_addRoute(0, 32, gw_ip); // handle default route
        else
            flowQoS_router_delRoute(0, 32);
        return;
    }
    cmdline_printf(cl, "Not Support IPv6\n");
}

cmdline_parse_token_string_t default_route_cmd_action =
    TOKEN_STRING_INITIALIZER(struct default_route_cmd, action, "route");
cmdline_parse_token_string_t default_route_cmd_option =
    TOKEN_STRING_INITIALIZER(struct default_route_cmd, option, "add#del");
cmdline_parse_token_string_t default_route_cmd_default =
    TOKEN_STRING_INITIALIZER(struct default_route_cmd, _default, "default");
cmdline_parse_token_string_t default_route_cmd_gw =
    TOKEN_STRING_INITIALIZER(struct default_route_cmd, gw, "gw");
cmdline_parse_token_ipaddr_t default_route_cmd_gw_ip =
    TOKEN_IPADDR_INITIALIZER(struct default_route_cmd, gw_ip);

cmdline_parse_inst_t default_route_cmd_obj = {
    .f = default_route_cmd_parsed, /* function to call */
    .data = NULL,                  /* 2nd arg of func */
    .help_str = "eg: route add default gw 192.168.201.1",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&default_route_cmd_action,
        (void *)&default_route_cmd_option,
        (void *)&default_route_cmd_default,
        (void *)&default_route_cmd_gw,
        (void *)&default_route_cmd_gw_ip,
        NULL,
    },
};
// route del -net 192.168.201.0 netmask 255.255.255.0 gw 192.168.200.2
/**********************************************************/

/**
 * @brief dump route, arp and port info cmd
 *
 */
struct cmd_routing_simpleCmd
{
    cmdline_fixed_string_t cmd;
};

static void cmd_routing_simpleCmd_parsed(__rte_unused void *parsed_result,
                                         struct cmdline *cl,
                                         __rte_unused void *data)
{
    struct cmd_routing_simpleCmd *res = parsed_result;
    if (strcmp(res->cmd, "ifconfig") == 0)
    {
        flowQoS_router_dumpPortInfo(cl);
    }
    if (strcmp(res->cmd, "arp") == 0)
    {
        flowQoS_router_dumpARP(cl);
    }
    if (strcmp(res->cmd, "route") == 0)
    {
        flowQoS_router_dumpRoute(cl);
    }
}

cmdline_parse_token_string_t cmd_routing_simple_cmd =
    TOKEN_STRING_INITIALIZER(struct cmd_routing_simpleCmd, cmd, "route#ifconfig#arp");

cmdline_parse_inst_t cmd_routing_simple_obj = {
    .f = cmd_routing_simpleCmd_parsed, /* function to call */
    .data = NULL,                      /* 2nd arg of func */
    .help_str = "arp/ifconfig/route",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&cmd_routing_simple_cmd,
        NULL,
    },
};

void registRoutingModule(bool needCmdline)
{
    for (int i = 0; i < port_num; i++)
    {
        initLocalPortInfo(i);
        rte_rwlock_init(&(arp_tables[i].lock));
    }
    flowQoS_router_initRoutingTable();

    if (needCmdline)
    {
        flowQoS_registCmd(&cmd_routing_simple_obj);
        flowQoS_registCmd(&default_route_cmd_obj);
        flowQoS_registCmd(&ifconfig_cmd_obj);
        flowQoS_registCmd(&arp_cmd_obj);
        flowQoS_registCmd(&route_cmd_obj);
    }
}

packet_action flowQoS_ARP_ICMP_PROCESS(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod_offset(m, struct rte_ether_hdr *, 0);
    if (eth->ether_type == htons(RTE_ETHER_TYPE_ARP))
    {
        struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
        // uint32_t tip = rte_be_to_cpu_32(arp->arp_data.arp_tip);
        // DOCA_LOG_INFO("Port %d recv one ARP request pkt on IP %d.%d.%d.%d", m->port,
        //               (tip & 0xff000000) >> 24,
        //               (tip & 0x00ff0000) >> 16,
        //               (tip & 0x0000ff00) >> 8,
        //               (tip & 0x000000ff));
        if (rte_be_to_cpu_32(arp->arp_data.arp_tip) == flowQoS_router_getLocalIP(m->port))
        {
            // DOCA_LOG_INFO("Port %d Reply ARP", m->port);
            arp->arp_hardware = htons(1);
            arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
            arp->arp_hlen = RTE_ETHER_ADDR_LEN;
            arp->arp_plen = sizeof(uint32_t);
            arp->arp_opcode = htons(2); // 1 is Req and 2 is Rep

            flowQoS_router_put_arp(m->port, rte_be_to_cpu_32(arp->arp_data.arp_sip), eth->s_addr.addr_bytes);

            rte_memcpy(eth->d_addr.addr_bytes, eth->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
            rte_memcpy(eth->s_addr.addr_bytes, localPortInfo[m->port].mac, RTE_ETHER_ADDR_LEN);

            rte_memcpy(arp->arp_data.arp_sha.addr_bytes, eth->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
            rte_memcpy(arp->arp_data.arp_tha.addr_bytes, eth->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

            uint32_t tmp_ip = arp->arp_data.arp_sip;
            arp->arp_data.arp_sip = arp->arp_data.arp_tip;
            arp->arp_data.arp_tip = tmp_ip;

            return m->port;
        }
    }
    else if (RTE_ETH_IS_IPV4_HDR(m->packet_type))
    {
        struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
        if (ip->next_proto_id == 1 && rte_be_to_cpu_32(ip->dst_addr) == flowQoS_router_getLocalIP(m->port))
        {
            struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod_offset(m, struct rte_icmp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
            if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REQUEST)
            {
                // DOCA_LOG_INFO("Port %d recv one ICMP request pkt, rss:%u", m->port, m->hash.rss);
                //  Swap MAC
                struct rte_ether_hdr *eth = rte_pktmbuf_mtod_offset(m, struct rte_ether_hdr *, 0);
                uint8_t tmp_mac[RTE_ETHER_ADDR_LEN];
                rte_memcpy(tmp_mac, eth->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
                rte_memcpy(eth->s_addr.addr_bytes, eth->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
                rte_memcpy(eth->d_addr.addr_bytes, tmp_mac, RTE_ETHER_ADDR_LEN);

                // Swap IP
                ip->packet_id = 0;
                ip->fragment_offset = 0;
                ip->time_to_live = 64;
                uint32_t tmp_ip = ip->src_addr;
                ip->src_addr = ip->dst_addr;
                ip->dst_addr = tmp_ip;
                ip->hdr_checksum = 0;

                m->l2_len = sizeof(struct rte_ether_hdr);
                m->l3_len = sizeof(struct rte_ipv4_hdr);
                m->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM; // offload checksum

                // Handle ICMP
                icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
                icmp->icmp_cksum = icmp->icmp_cksum + htons(0x0800);
                return m->port;
            }
        }
    }
    return IGNORE_PACKETS;
}