/**
 * @file flowQoS_snat.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief snat based on flowQoS
 * @version 0.1
 * @date 2024-01-26
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <stdio.h>
#include <rte_random.h>
#include "flowQoS_env.h"
#include "flowQoS_pipe.h"
#include "flowQoS_cmd.h"
#include "flowQoS_router.h"
#include "flowQoS_conntrack.h"
#include "flowQoS_qos.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

DOCA_LOG_REGISTER(FLOWQOS_SNAT);

#define WAN_PORT 1                               ///< wan port id
#define LAN_PORT 0                               ///< lan port id
#define MAX_CT_OFFLOADED (1 << 16)               ///< maximum amount of conns can be offloaded
#define MAX_ENTRY_IN_PIPE MAX_CT_OFFLOADED + 10  ///< maximum amount of doca-flow entries
#define MAX_CT_IN_POOL MAX_CT_OFFLOADED * 2 + 10 ///< maximum amount of conns in pool
#define CONN_EXPIRE 50

struct snat_match
{
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
};

struct snat_pool_entry
{
    uint32_t sip;               ///< sip of upstream
    uint32_t dip;               ///< dip of downstream
    uint16_t sport;             ///< sport of upstream
    uint16_t dport;             ///< dport of downstream
    LIST_ENTRY(snat_pool_entry) ///< list of pool entry
    index;
};

struct flowQoS_snat_attr
{
    struct rte_hash *snat_table;                        ///< snat table, each connection will have 2 items including upstream and downstream stored in it
    struct snat_pool_entry *entries;                    ///< mem of entries
    LIST_HEAD(snat_pool_entry_buckets, snat_pool_entry) ///< list head of snat pool entries
    bucket;
} attr = {0};

/**
 * @brief put back a src address into snat pool
 *
 * @param entry
 */
void flowQoS_snat_pool_put(struct snat_pool_entry *entry)
{
    LIST_INSERT_HEAD(&(attr.bucket), entry, index);
}
/**
 * @brief get a src address from snat pool
 *
 * @return struct snat_pool_entry*
 */
struct snat_pool_entry *flowQoS_snat_pool_get()
{
    if (LIST_EMPTY(&(attr.bucket)))
        return NULL;
    struct snat_pool_entry *entry = LIST_FIRST(&(attr.bucket));
    LIST_REMOVE(entry, index);
    return entry;
}
/**
 * @brief init snat pool which is a lone linked-list with 65536 different src addresses and init snat_table
 *
 * @return int
 */
int flowQoS_snat_pool_init()
{
    const struct rte_hash_parameters snat_table =
        {
            .name = "snat_table",
            .entries = MAX_CT_IN_POOL,
            .reserved = 0,
            .key_len = sizeof(struct snat_match),
            .hash_func = rte_jhash,
            .hash_func_init_val = 0,
            .socket_id = rte_socket_id(),
            .extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE, // 0,
        };

    attr.snat_table = rte_hash_create(&snat_table);
    if (!attr.snat_table)
    {
        DOCA_LOG_ERR("Create snat_table fail!");
        return 0;
    }

    DOCA_LOG_INFO("Create snat_table success");

    attr.entries = (struct snat_pool_entry *)rte_malloc(NULL, 65536 * sizeof(struct snat_pool_entry), 0);
    if (attr.entries == NULL)
    {
        DOCA_LOG_ERR("Allocate snat pool ERR");
        return 0;
    }

    LIST_INIT(&(attr.bucket));

    uint32_t sip = flowQoS_router_getLocalIP(WAN_PORT);
    for (int i = 0; i < 65536; i++)
    {
        attr.entries[i].sip = rte_cpu_to_be_32(sip);
        attr.entries[i].sport = i;
        flowQoS_snat_pool_put(&(attr.entries[i]));
    }

    int count = 0;
    struct snat_pool_entry *entry = NULL;
    LIST_FOREACH(entry, &(attr.bucket), index)
    {
        count++;
    }
    DOCA_LOG_INFO("SNAT POOL COUNT: %d", count);
    return count;
}

/**
 * @brief debug api for printing FlowQoS_ENTRY
 *
 * @param help
 * @param newEntry
 */
void debug_snat(char *help, struct FlowQoS_ENTRY *newEntry)
{
    DOCA_LOG_INFO("===========>%s", help);
    struct EntryInfo info;
    dumpFlowQoSEntry(newEntry, &info);
    printFlowQoSEntry(&info);
}

/**
 * @brief handle new conns
 *
 * @param newEntry
 * @return packet_action
 */
packet_action newConn_handler(struct FlowQoS_ENTRY *newEntry)
{
    int port_id = newEntry->pipe->port_id;
    // if (newEntry->match.dst_port == rte_cpu_to_be_16(4789)) //drop irrelevant vxlan packets
    //     return DROP_PACKETS;
    // debug_snat("in", newEntry);
    if (port_id == LAN_PORT)
    {
        struct snat_pool_entry *entry = NULL;
        struct snat_match match = {0}, reverse_match = {0};
        uint8_t mac[6];

        if (flowQoS_router_get_arp(WAN_PORT, rte_be_to_cpu_32(newEntry->match.dst_ip), mac) == 0)
        {
            // DOCA_LOG_ERR("Cannot find arp ERR");
            return DROP_PACKETS;
        }

        entry = flowQoS_snat_pool_get(); // get a src address from pool
        if (entry == NULL)
        {
            DOCA_LOG_ERR("snat pool is empty ERR");
            return DROP_PACKETS;
        }
        entry->dip = newEntry->match.src_ip;
        entry->dport = newEntry->match.src_port;

        /*********LAN to WAN****************/
        match.sip = newEntry->match.src_ip;
        match.sport = newEntry->match.src_port;
        match.proto = newEntry->match.proto;
        match.dip = newEntry->match.dst_ip;
        match.dport = newEntry->match.dst_port;

        int ret = rte_hash_add_key_data(attr.snat_table, &(match), entry); // put upstream into snat_table
        if (ret < 0)
        {
            DOCA_LOG_ERR("Failed to add upstream conn into snat_table...");
            flowQoS_snat_pool_put(entry);
            return DROP_PACKETS;
        }
        /*********WAN to LAN****************/
        reverse_match.sip = newEntry->match.dst_ip;
        reverse_match.sport = newEntry->match.dst_port;
        reverse_match.proto = newEntry->match.proto;
        reverse_match.dip = entry->sip;
        reverse_match.dport = entry->sport;

        ret = rte_hash_add_key_data(attr.snat_table, &(reverse_match), entry); // put downstream into snat_table
        if (ret < 0)
        {
            DOCA_LOG_ERR("Failed to add downstream conn into snat_table...");
            rte_hash_del_key(attr.snat_table, &(match));
            flowQoS_snat_pool_put(entry);
            return DROP_PACKETS;
        }

        // offload upstream
        newEntry->expireTime = CONN_EXPIRE;
        newEntry->action.src_ip = entry->sip;
        newEntry->action.src_port = entry->sport;

        rte_memcpy(newEntry->action.dst_mac, mac, DOCA_ETHER_ADDR_LEN);

        // debug_snat("out_wan", newEntry);
        return WAN_PORT;
    }
    else
    {
        struct snat_match match = {0};
        struct snat_pool_entry *entry = NULL;
        uint8_t mac[6];

        /*********LAN to WAN****************/
        match.sip = newEntry->match.src_ip;
        match.sport = newEntry->match.src_port;
        match.proto = newEntry->match.proto;
        match.dip = newEntry->match.dst_ip;
        match.dport = newEntry->match.dst_port;

        int ret = rte_hash_lookup_data(attr.snat_table, &(match), (void **)&entry); // find exisited downstream
        if (ret < 0)
        {
            DOCA_LOG_ERR("Not find reversed match");
            return DROP_PACKETS;
        }
        // offload downstream
        newEntry->expireTime = CONN_EXPIRE;
        newEntry->action.dst_ip = entry->dip;
        newEntry->action.dst_port = entry->dport;

        if (flowQoS_router_get_arp(LAN_PORT, rte_be_to_cpu_32(newEntry->action.dst_ip), mac) == 0)
        {
            DOCA_LOG_ERR("Cannot find arp ERR");
            return DROP_PACKETS;
        }
        rte_memcpy(newEntry->action.dst_mac, mac, DOCA_ETHER_ADDR_LEN);

        // debug_snat("out_lan", newEntry);
        return LAN_PORT;
    }
    return IGNORE_PACKETS;
}

/**
 * @brief handle aged conns
 * 
 * @param newEntry 
 */
void agingConn_handler(struct FlowQoS_ENTRY *newEntry)
{
    if (newEntry->pipe->port_id == LAN_PORT)
    {

        struct snat_match match = {0}, reverse_match = {0};
        struct snat_pool_entry *entry = NULL;

        match.sip = newEntry->match.src_ip;
        match.sport = newEntry->match.src_port;
        match.proto = newEntry->match.proto;
        match.dip = newEntry->match.dst_ip;
        match.dport = newEntry->match.dst_port;

        int ret = rte_hash_lookup_data(attr.snat_table, &(match), (void **)&entry);
        if (ret < 0)
        {
            DOCA_LOG_ERR("Not find aged match");
            return;
        }

        reverse_match.sip = newEntry->match.dst_ip;
        reverse_match.sport = newEntry->match.dst_port;
        reverse_match.proto = newEntry->match.proto;
        reverse_match.dip = entry->sip;
        reverse_match.dport = entry->sport;

        rte_hash_del_key(attr.snat_table, &(match));
        rte_hash_del_key(attr.snat_table, &(reverse_match));

        flowQoS_snat_pool_put(entry);
    }
}

/****************************snat******************************/

/**
 * @brief cmds of snat
 *
 */
struct cmd_snat
{
    cmdline_fixed_string_t cmd;
};

static void cmd_snat_parsed(__rte_unused void *parsed_result,
                            struct cmdline *cl,
                            __rte_unused void *data)
{
    cmdline_printf(cl, "Snat Table Count:[%d]\n", rte_hash_count(attr.snat_table));
    int count = 0;
    struct snat_pool_entry *entry = NULL;
    LIST_FOREACH(entry, &(attr.bucket), index)
    {
        count++;
    }
    cmdline_printf(cl, "Snat Pool Count:[%d]\n", count);
}

cmdline_parse_token_string_t cmd_snat_cmd =
    TOKEN_STRING_INITIALIZER(struct cmd_snat, cmd, "show");

cmdline_parse_inst_t cmd_snat_obj = {
    .f = cmd_snat_parsed, /* function to call */
    .data = NULL,         /* 2nd arg of func */
    .help_str = "Show info of snat",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&cmd_snat_cmd,
        NULL,
    },
};

/**
 * @brief register cmds of snat into dpdk cmdline
 *
 */
void registerSnatCmd()
{
    static bool cmdRegistered = false;
    if (!cmdRegistered)
    {
        flowQoS_registCmd(&cmd_snat_obj);
        cmdRegistered = true;
        DOCA_LOG_INFO("Register snat cmd");
    }
}

/**
 * @brief init snat app
 * 
 * @return int 
 */
int init_snat()
{
    if (rte_lcore_count() != 2)
    {
        DOCA_LOG_ERR("Only support 1 master core and 1 slave core......");
        return 0;
    }
    if (flowQoS_conntrack_init_env(MAX_CT_IN_POOL, MAX_CT_OFFLOADED, 0, 0) <= 0)
        return 0;
    if (flowQoS_conntrack_init_port(LAN_PORT, MAX_ENTRY_IN_PIPE, SIP | SPORT | DMAC | AGING) < 0)
        return 0;
    if (flowQoS_conntrack_init_port(WAN_PORT, MAX_ENTRY_IN_PIPE, DIP | DPORT | DMAC | AGING) < 0)
        return 0;

    flowQoS_regist_newConn_handler(newConn_handler);
    flowQoS_regist_agingConn_handler(agingConn_handler);

    registRoutingModule(true);

    registerSnatCmd();

    register_packet_processor(flowQoS_ARP_ICMP_PROCESS);

    flowQoS_router_ifconfig("dpdk0", RTE_IPV4(192, 168, 200, 2), 24);
    flowQoS_router_ifconfig("dpdk1", RTE_IPV4(192, 168, 201, 2), 24);
    uint8_t mac1[6] = {0x08, 0xc0, 0xeb, 0xbf, 0xef, 0x9a},
            mac2[6] = {0x08, 0xc0, 0xeb, 0xbf, 0xef, 0x82},
            mac3[6] = {0xb8, 0xce, 0xf6, 0xd5, 0xd6, 0xf7},
            mac4[6] = {0xb8, 0xce, 0xf6, 0xd5, 0xcc, 0x5f},
            mac5[6] = {0x08, 0xc0, 0xeb, 0xbf, 0xef, 0x83};

    flowQoS_router_put_arp(0, RTE_IPV4(192, 168, 200, 1), mac2);
    flowQoS_router_put_arp(0, RTE_IPV4(192, 168, 200, 102), mac3);
    flowQoS_router_put_arp(0, RTE_IPV4(192, 168, 200, 103), mac4);
    flowQoS_router_put_arp(1, RTE_IPV4(192, 168, 201, 1), mac5);

    flowQoS_router_setPortMac(0, mac1);

    return flowQoS_snat_pool_init();
}

int main(int argc, char **argv)
{
    flowQoS_env_init(argc, argv);

    if (init_snat() <= 0)
        goto EXIT;

    launch_worker();
    flowQoS_cmd();
    stop_worker();

EXIT:
    flowQoS_env_destroy();
    return 0;
}