/**
 * @file flowQoS_firewall.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief stateless firewall based on flowQoS
 * @version 0.1
 * @date 2024-01-24
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <stdio.h>
#include "flowQoS_env.h"
#include "flowQoS_pipe.h"
#include "flowQoS_cmd.h"
#define PORT_TO_HOST 1    ///< port connected with host
#define PORT_TO_NET 0     ///< port connected with net
#define MAX_RULES 1 << 10 ///< maximum amount of entries in doca-flow pipe

DOCA_LOG_REGISTER(FLOWQOS_FIREWALL);
enum traffic_direction
{
    INPUT, ///< from net to host
    OUTPUT ///< from host to net
};
/// @brief firewall rule
struct firewall_rule
{
    enum traffic_direction direction;
    uint8_t proto;              ///< 6:TCP, 17:UDP
    uint32_t sip;               ///< src ip
    uint16_t sport;             ///< src port
    struct FlowQoS_ENTRY entry; ///< flwoQoS_ENTRY
    LIST_ENTRY(firewall_rule) index; ///< List entry
};

/// @brief attrs of firewall
struct flowQoS_firewall_attr
{
    struct FlowQoS_PIPE *tcp_drop_pipe[2];///<drop tcp 
    struct FlowQoS_PIPE *udp_drop_pipe[2];///<drop udp
    struct FlowQoS_PIPE *hairpin_pipe[2];///< accept others
    LIST_HEAD(rules_bucket, firewall_rule) bucket; ///< rules list head
} fw_attr = {0};

/**
 * @brief add a dropping rule
 * 
 * @param direction 
 * @param proto 
 * @param sip 
 * @param sport 
 * @return int 
 */
int flowQoS_firewall_add_rule(enum traffic_direction direction, uint8_t proto, uint32_t sip, uint16_t sport)
{
    struct firewall_rule *rule = (struct firewall_rule *)malloc(sizeof(struct firewall_rule)); /* Insert at the head. */
    struct EntryInfo entryInfo = {0};
    if (rule == NULL)
    {
        DOCA_LOG_ERR("Allocate rule fail");
        return 0;
    }
    memset(&(rule->entry), 0, sizeof(struct FlowQoS_ENTRY));

    rule->direction = direction;
    rule->proto = proto;
    rule->sip = sip;
    rule->sport = sport;

    rule->entry.match.src_ip = sip;
    rule->entry.match.src_port = sport;
    int ret = 0;
    if (direction == INPUT)
    {
        if (proto == 6)
        {
            ret = flowQoS_add_entry(fw_attr.tcp_drop_pipe[PORT_TO_HOST], &(rule->entry), 0, 1);
        }
        else
        {
            ret = flowQoS_add_entry(fw_attr.udp_drop_pipe[PORT_TO_HOST], &(rule->entry), 0, 1);
        }
    }
    else
    {
        if (proto == 6)
        {
            ret = flowQoS_add_entry(fw_attr.tcp_drop_pipe[PORT_TO_NET], &(rule->entry), 0, 1);
        }
        else
        {
            ret = flowQoS_add_entry(fw_attr.udp_drop_pipe[PORT_TO_NET], &(rule->entry), 0, 1);
        }
    }
    if (ret)
    {
        dumpFlowQoSEntry(&(rule->entry), &entryInfo);
        printFlowQoSEntry(&entryInfo);
        LIST_INSERT_HEAD(&(fw_attr.bucket), rule, index);
        DOCA_LOG_INFO("Add rule success");
    }
    else
    {
        free(rule);
        DOCA_LOG_ERR("Add rule fail");
    }
    return ret;
}
/**
 * @brief print all rules
 * 
 */
void flowQoS_firewall_print_rules()
{
    struct firewall_rule *rule = NULL;
    struct EntryInfo entryInfo = {0};
    int idx = 0;
    LIST_FOREACH(rule, &(fw_attr.bucket), index)
    {
        dumpFlowQoSEntry(&(rule->entry), &entryInfo);
        printf("%-5d %-5s %-5s %-25s %-15s\n", idx, rule->direction == INPUT ? "INPUT" : "OUTPUT", rule->proto == 6 ? "TCP" : "UDP", entryInfo.match.sip, entryInfo.match.sport);
        idx++;
    }
}
/**
 * @brief del rule by index
 * 
 * @param rule_id 
 */
void flowQoS_firewall_del_rule(int rule_id)
{
    struct firewall_rule *rule = NULL;
    struct EntryInfo entryInfo = {0};
    int idx = 0;
    LIST_FOREACH(rule, &(fw_attr.bucket), index)
    {
        if (idx == rule_id)
        {
            dumpFlowQoSEntry(&(rule->entry), &entryInfo);
            printf("%-5d %-5s %-5s %-25s %-15s\n", idx, rule->direction == INPUT ? "INPUT" : "OUTPUT", rule->proto == 6 ? "TCP" : "UDP", entryInfo.match.sip, entryInfo.match.sport);
            if (doca_flow_pipe_rm_entry(0, NULL, rule->entry.entry) < 0)
            {
                DOCA_LOG_ERR("Del fail");
            }
            else
            {
                LIST_REMOVE(rule, index);
                free(rule);
                DOCA_LOG_INFO("Del success");
            }
            break;
        }
        idx++;
    }
}

/*****************************************************/ // add rules

/// @brief cmd of add a rule
struct add_cmd
{
    cmdline_fixed_string_t action;
    cmdline_fixed_string_t direction;
    cmdline_fixed_string_t proto;
    cmdline_ipaddr_t sip;
    uint16_t sport;
};

static void add_cmd_parsed(__rte_unused void *parsed_result,
                           struct cmdline *cl,
                           __rte_unused void *data)
{
    struct add_cmd *res = parsed_result;
    if (res->sip.family == AF_INET)
    {

        uint32_t sip = res->sip.addr.ipv4.s_addr;
        uint16_t sport = rte_be_to_cpu_16(res->sport);
        flowQoS_firewall_add_rule(strcmp(res->direction, "INPUT") == 0 ? INPUT : OUTPUT, strcmp(res->proto, "TCP") == 0 ? 6 : 17, sip, sport);
        return;
    }
    cmdline_printf(cl, "Not Support IPv6\n");
}

cmdline_parse_token_string_t add_cmd_action =
    TOKEN_STRING_INITIALIZER(struct add_cmd, action, "add");
cmdline_parse_token_string_t add_cmd_direction =
    TOKEN_STRING_INITIALIZER(struct add_cmd, direction, "INPUT#OUTPUT");
cmdline_parse_token_string_t add_cmd_proto =
    TOKEN_STRING_INITIALIZER(struct add_cmd, proto, "TCP#UDP");
cmdline_parse_token_ipaddr_t add_cmd_sip =
    TOKEN_IPADDR_INITIALIZER(struct add_cmd, sip);
cmdline_parse_token_num_t add_cmd_sport =
    TOKEN_NUM_INITIALIZER(struct add_cmd, sport, RTE_INT16);
cmdline_parse_inst_t add_cmd_obj = {
    .f = add_cmd_parsed, /* function to call */
    .data = NULL,        /* 2nd arg of func */
    .help_str = "eg: add [INPUT|OUTPUT] [TCP|UDP] 192.168.201.1 5001",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&add_cmd_action,
        (void *)&add_cmd_direction,
        (void *)&add_cmd_proto,
        (void *)&add_cmd_sip,
        (void *)&add_cmd_sport,
        NULL,
    },
};

/// @brief cmd of print rules
struct print_cmd
{
    cmdline_fixed_string_t action;
};
static void print_cmd_parsed(__rte_unused void *parsed_result,
                             struct cmdline *cl,
                             __rte_unused void *data)
{
    flowQoS_firewall_print_rules();
}
cmdline_parse_token_string_t print_cmd_action =
    TOKEN_STRING_INITIALIZER(struct print_cmd, action, "show");
cmdline_parse_inst_t print_cmd_obj = {
    .f = print_cmd_parsed, /* function to call */
    .data = NULL,          /* 2nd arg of func */
    .help_str = "eg: show",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&print_cmd_action,
        NULL,
    },
};

/// @brief cmd of del a rule by index
struct del_cmd
{
    cmdline_fixed_string_t action;
    uint16_t idx;
};
static void del_cmd_parsed(__rte_unused void *parsed_result,
                           struct cmdline *cl,
                           __rte_unused void *data)
{
    struct del_cmd *res = parsed_result;
    flowQoS_firewall_del_rule(res->idx);
}
cmdline_parse_token_string_t del_cmd_action =
    TOKEN_STRING_INITIALIZER(struct del_cmd, action, "del");

cmdline_parse_token_num_t del_cmd_idx =
    TOKEN_NUM_INITIALIZER(struct del_cmd, idx, RTE_INT16);

cmdline_parse_inst_t del_cmd_obj = {
    .f = del_cmd_parsed, /* function to call */
    .data = NULL,        /* 2nd arg of func */
    .help_str = "eg: del 1",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&del_cmd_action,
        (void *)&del_cmd_idx,
        NULL,
    },
};

int main(int argc, char **argv)
{
    flowQoS_env_init(argc, argv);
    struct FlowQoS_ENTRY hairpin_entry[2] = {0};
    for (int i = 0; i < 2; i++)
    {
        fw_attr.hairpin_pipe[i] = flowQoS_build_pipe(i, "hairpin_pipe", 0, 0, PORT, DROP, !IS_ROOT, 2);
        if (fw_attr.hairpin_pipe[i] == NULL)
            goto EXIT;
        fw_attr.tcp_drop_pipe[i] = flowQoS_build_pipe(i, "tcp_drop_pipe", SIP | TCP | SPORT, 0, DROP, (FlowQoS_FWD)(fw_attr.hairpin_pipe[i]), IS_ROOT, MAX_RULES * 2);
        if (fw_attr.tcp_drop_pipe[i] == NULL)
            goto EXIT;
        fw_attr.udp_drop_pipe[i] = flowQoS_build_pipe(i, "udp_drop_pipe", SIP | UDP | SPORT, 0, DROP, (FlowQoS_FWD)(fw_attr.hairpin_pipe[i]), IS_ROOT, MAX_RULES * 2);
        if (fw_attr.udp_drop_pipe[i] == NULL)
            goto EXIT;
        flowQoS_add_entry(fw_attr.hairpin_pipe[i], &(hairpin_entry[i]), 0, 1);
    }
    LIST_INIT(&(fw_attr.bucket));
    flowQoS_registCmd(&add_cmd_obj);
    flowQoS_registCmd(&print_cmd_obj);
    flowQoS_registCmd(&del_cmd_obj);
    flowQoS_cmd();
EXIT:
    flowQoS_env_destroy();
    return 0;
}