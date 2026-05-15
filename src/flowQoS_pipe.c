/**
 * @file flowQoS_pipe.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief encapsulation of doca-flow API
 * @version 0.1
 * @date 2024-01-21
 *
 * @copyright Copyright (c) 2024
 *
 */
#include "flowQoS_pipe.h"
#include "flowQoS_env.h"
#include "flowQoS_cmd.h"
#include <rte_lcore.h>
#include <doca_log.h>
#include <rte_malloc.h>
DOCA_LOG_REGISTER(FLOWQOS_PIPE);

/**
 * @brief includes action and monitor
 * 
 */
struct doca_flow_action_meta
{
    struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
    struct doca_flow_action_descs descs;
    struct doca_flow_action_descs *descs_arr[NB_ACTIONS_ARR];
    struct doca_flow_monitor monitor;
};

/**
 * @brief register cmds of pipe module onto dpdk cmdlines
 * 
 */
void registerPipeCmd();

void dumpFDB()
{
    for (int i = 0; i < NB_PORTS; i++)
        doca_flow_port_pipes_dump(ports[i], stdout);
}

/**
 * @brief transform FlowQoS_MATCH to doca_flow_match
 * 
 * @param flowQoS_match 
 * @param doca_match 
 * @param isEntry match is from doca-flow entry if true, match is from doca-flow pipe if false
 */
void match_adapter(struct FlowQoS_MATCH *flowQoS_match, struct doca_flow_match *doca_match, int isEntry)
{
    if (flowQoS_match->flags & SIP)
    {
        doca_match->out_src_ip.type = DOCA_FLOW_IP4_ADDR;
        doca_match->out_src_ip.ipv4_addr = isEntry > 0 ? flowQoS_match->src_ip : 0xffffffff;
    }
    if (flowQoS_match->flags & DIP)
    {
        doca_match->out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
        doca_match->out_dst_ip.ipv4_addr = isEntry > 0 ? flowQoS_match->dst_ip : 0xffffffff;
    }
    if (flowQoS_match->flags & TCP)
    {
        if (isEntry == 0)
        {
            doca_match->out_l4_type = DOCA_PROTO_TCP;
        }
    }
    if (flowQoS_match->flags & UDP)
    {
        if (isEntry == 0)
        {
            doca_match->out_l4_type = DOCA_PROTO_UDP;
        }
    }
    if (flowQoS_match->flags & SPORT)
    {
        doca_match->out_src_port = isEntry > 0 ? flowQoS_match->src_port : 0xffff;
    }
    if (flowQoS_match->flags & DPORT)
    {
        doca_match->out_dst_port = isEntry > 0 ? flowQoS_match->dst_port : 0xffff;
    }
}
/**
 * @brief transform FlowQoS_ACTION to doca-flow action and doca-flow monitor
 * 
 * @param flowQoS_action 
 * @param doca_action_meta 
 * @param agingTime action is from doca-flow entry if true, action is from doca-flow pipe if false
 */
void action_adapter(struct FlowQoS_ACTION *flowQoS_action, struct doca_flow_action_meta *doca_action_meta, int agingTime)
{
    doca_action_meta->actions_arr[0] = &(doca_action_meta->actions);
    doca_action_meta->descs_arr[0] = &(doca_action_meta->descs);

    if (flowQoS_action->flags & SMAC)
    {
        for (int i = 0; i < DOCA_ETHER_ADDR_LEN; i++)
        {
            doca_action_meta->actions.mod_src_mac[i] = agingTime > 0 ? flowQoS_action->src_mac[i] : 0xff;
        }
    }
    if (flowQoS_action->flags & DMAC)
    {
        for (int i = 0; i < DOCA_ETHER_ADDR_LEN; i++)
        {
            doca_action_meta->actions.mod_dst_mac[i] = agingTime > 0 ? flowQoS_action->dst_mac[i] : 0xff;
        }
    }

    if (flowQoS_action->flags & SIP)
    {
        doca_action_meta->actions.mod_src_ip.type = DOCA_FLOW_IP4_ADDR;
        doca_action_meta->actions.mod_src_ip.ipv4_addr = agingTime > 0 ? flowQoS_action->src_ip : 0xffffffff;
    }
    if (flowQoS_action->flags & DIP)
    {
        doca_action_meta->actions.mod_dst_ip.type = DOCA_FLOW_IP4_ADDR;
        doca_action_meta->actions.mod_dst_ip.ipv4_addr = agingTime > 0 ? flowQoS_action->dst_ip : 0xffffffff;
    }
    if (flowQoS_action->flags & TTL_DECREASE)
    {
        if (agingTime == 0)
        {
            doca_action_meta->descs.ttl.type = DOCA_FLOW_ACTION_ADD;
            doca_action_meta->actions.ttl = UINT8_MAX;
        }
    }
    if (flowQoS_action->flags & SPORT)
    {
        doca_action_meta->actions.mod_src_port = agingTime > 0 ? flowQoS_action->src_port : 0xffff;
    }
    if (flowQoS_action->flags & DPORT)
    {
        doca_action_meta->actions.mod_dst_port = agingTime > 0 ? flowQoS_action->dst_port : 0xffff;
    }

    if (flowQoS_action->flags & COUNTER)
    {
        if (agingTime == 0)
        {
            doca_action_meta->monitor.flags |= DOCA_FLOW_MONITOR_COUNT;
        }
    }
    if (flowQoS_action->flags & AGING)
    {
        doca_action_meta->monitor.flags |= DOCA_FLOW_MONITOR_AGING;
        if (agingTime != 0)
        {
            doca_action_meta->monitor.flags |= DOCA_FLOW_MONITOR_AGING;
            doca_action_meta->monitor.aging = agingTime;
        }
    }
}
/**
 * @brief transform FlowQoS_FWD to doca_flow_fwd
 * 
 * @param flowQoS_FWD 
 * @param doca_fwd 
 * @param port_id 
 */
void fwd_adapter(FlowQoS_FWD flowQoS_FWD, struct doca_flow_fwd *doca_fwd, int port_id)
{
    if (flowQoS_FWD == DROP)
    {
        doca_fwd->type = DOCA_FLOW_FWD_DROP;
    }
    else if (flowQoS_FWD == PORT)
    {
        doca_fwd->type = DOCA_FLOW_FWD_PORT;
        doca_fwd->port_id = port_id ^ 1;
    }
    else if (flowQoS_FWD == RSS_TO_QUEUE)
    {
        static uint16_t rss_queues[16]; // Don't forget to make it static, or it will be released after being revoked and cause issues to RSS.
        for (int i = 0; i < rte_lcore_count() - 1; i++)
            rss_queues[i] = i;
        doca_fwd->type = DOCA_FLOW_FWD_RSS;
        doca_fwd->rss_queues = rss_queues;
        doca_fwd->rss_flags = DOCA_FLOW_RSS_IP | DOCA_FLOW_RSS_TCP | DOCA_FLOW_RSS_UDP;
        doca_fwd->num_of_queues = rte_lcore_count() - 1;
    }
    else
    {
        struct FlowQoS_PIPE *next_pipe = (struct FlowQoS_PIPE *)flowQoS_FWD;
        doca_fwd->type = DOCA_FLOW_FWD_PIPE;
        doca_fwd->next_pipe = next_pipe->doca_pipe;
    }
}

struct FlowQoS_PIPE *flowQoS_build_pipe(int port_id, char *pipe_name,
                                        uint64_t matchFlags, uint64_t actionFlags,
                                        FlowQoS_FWD matched, FlowQoS_FWD unmatched,
                                        bool is_root, int entryAmount)
{

    struct doca_flow_error error;
    struct doca_flow_match match;
    struct doca_flow_action_meta action_meta;
    struct doca_flow_fwd fwd, fwd_miss;
    struct doca_flow_pipe_cfg pipe_cfg = {0};
    struct FlowQoS_PIPE *flowQoS_pipe = (struct FlowQoS_PIPE *)rte_malloc(NULL, sizeof(struct FlowQoS_PIPE), 0);

    if (flowQoS_pipe == NULL)
    {
        DOCA_LOG_ERR("Malloc Pipe Error");
        return NULL;
    }

    registerPipeCmd();

    memset(flowQoS_pipe, 0, sizeof(struct FlowQoS_PIPE));
    memset(&match, 0, sizeof(match));
    memset(&action_meta, 0, sizeof(action_meta));
    memset(&fwd, 0, sizeof(fwd));
    memset(&fwd_miss, 0, sizeof(fwd));
    memset(&pipe_cfg, 0, sizeof(pipe_cfg));

    flowQoS_pipe->match_pattern.flags = matchFlags;
    flowQoS_pipe->action_pattern.flags = actionFlags;
    flowQoS_pipe->matched_fwd = matched;
    flowQoS_pipe->unmatched_fwd = unmatched;
    flowQoS_pipe->src_doca_port = ports[port_id];
    flowQoS_pipe->dst_doca_port = ports[port_id ^ 1];
    flowQoS_pipe->is_root = is_root;
    flowQoS_pipe->max_entry_amount = entryAmount;
    flowQoS_pipe->port_id = port_id;
    sprintf(flowQoS_pipe->pipeName, "%s", pipe_name);

    match_adapter(&(flowQoS_pipe->match_pattern), &match, 0);
    action_adapter(&(flowQoS_pipe->action_pattern), &action_meta, 0);
    fwd_adapter(flowQoS_pipe->matched_fwd, &fwd, port_id);
    fwd_adapter(flowQoS_pipe->unmatched_fwd, &fwd_miss, port_id);

    pipe_cfg.attr.name = pipe_name;
    pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
    pipe_cfg.match = &match;
    pipe_cfg.actions = action_meta.actions_arr;
    pipe_cfg.action_descs = action_meta.descs_arr;
    pipe_cfg.attr.nb_flows = flowQoS_pipe->max_entry_amount;
    pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
    pipe_cfg.attr.is_root = flowQoS_pipe->is_root;
    pipe_cfg.port = ports[port_id];
    pipe_cfg.monitor = &(action_meta.monitor);

    flowQoS_pipe->doca_pipe = doca_flow_pipe_create(&pipe_cfg, &fwd, &fwd_miss, &error);
    if (flowQoS_pipe->doca_pipe == NULL)
    {
        DOCA_LOG_ERR("Build FlowQoS PIPE %s ERR,- %s (%u)", pipe_name, error.message, error.type);
        rte_free(flowQoS_pipe);
        return NULL;
    }
    printFlowQoSPipe(flowQoS_pipe);
    return flowQoS_pipe;
}

int flowQoS_add_entry(struct FlowQoS_PIPE *flowQoS_pipe, struct FlowQoS_ENTRY *entry, int flowQueueId, int flush)
{
    struct doca_flow_match match;
    struct doca_flow_action_meta action_meta;
    struct doca_flow_error error;
    int result, ret = 1;
    int num_of_entries = flush; // 1;
    enum doca_flow_flags_type flags = (flush > 0 ? DOCA_FLOW_NO_WAIT : DOCA_FLOW_WAIT_FOR_BATCH);

    entry->pipe = flowQoS_pipe;
    struct doca_flow_pipe *pipe = flowQoS_pipe->doca_pipe;

    memset(&match, 0, sizeof(match));
    memset(&action_meta, 0, sizeof(action_meta));

    entry->match.flags = flowQoS_pipe->match_pattern.flags;
    entry->action.flags = flowQoS_pipe->action_pattern.flags;

    match_adapter(&(entry->match), &match, 1);
    action_adapter(&(entry->action), &action_meta, entry->expireTime > 0 ? entry->expireTime : 1);

    if (entry->expireTime > 0)
        action_meta.monitor.user_data = (uint64_t)entry;

    entry->entry = doca_flow_pipe_add_entry(flowQueueId, pipe, &match, &(action_meta.actions), &(action_meta.monitor), NULL, flags, NULL, &error);

    if (entry->entry == NULL)
    {
        // DOCA_LOG_ERR("Entry is NULL,- %s (%u)", error.message, error.type);
        ret = 0;
    }
    if (flush)
    {
        if (entry->entry == NULL)
            num_of_entries--;
        result = doca_flow_entries_process(flowQoS_pipe->src_doca_port, flowQueueId, DEFAULT_TIMEOUT_US, num_of_entries);

        // DOCA_LOG_INFO("Entry:Flushed Entry=%d:%d", num_of_entries, result);
        if (result != num_of_entries)
            ret = 0;
    }

    return ret;
}

int flowQoS_aging_handle(int port_id, int flowQueueId)
{
    struct doca_flow_aged_query aged_entries[MAX_AGED_CT_PER_POLL];
    int num_of_aged_entries = doca_flow_aging_handle(ports[port_id], flowQueueId, 20 /*us*/,
                                                     aged_entries, MAX_AGED_CT_PER_POLL);
    /* call handle aging until full cycle complete */
    for (int i = 0; i < num_of_aged_entries; i++)
    {
        struct FlowQoS_ENTRY *entry = (struct FlowQoS_ENTRY *)aged_entries[i].user_data;
        if (doca_flow_pipe_rm_entry(flowQueueId, NULL, entry->entry) < 0)
        {
            DOCA_LOG_INFO("failed to remove aged entry");
            continue;
        }
        else if (entry->cb)
        {
            entry->cb(entry->cb_args); // Revoke user_defined callback
        }
    }
    return num_of_aged_entries > 0 ? num_of_aged_entries : 0;
}

void dumpFlowQoSEntry(struct FlowQoS_ENTRY *entry, struct EntryInfo *entryInfo)
{
    /*
      MATCH=[SIP:192.168.200.155,DIP:192.168.200.2,TCP,SPORT:77888,DPORT:80]
     Action=[SIP:192.168.200.1,DIP:192.168.200.2,SPORT:7788,DPORT:80,SMAC:b8:ce:f6:d5:cc:5f,DMAC:b8:ce:f6:d5:cc:5f,TTL]
    Control=[COUNTER,AGEING,MATCH:PORT,MISS:"Next_PIPE_NAME"]
    */
    memset(entryInfo, 0, sizeof(struct EntryInfo));
    ///////////////////////////////////////////////////Handle Match
    struct FlowQoS_MATCH *match = &(entry->match);
    if (match->flags & SIP)
    {
        uint32_t sip = rte_be_to_cpu_32(match->src_ip);
        sprintf(entryInfo->match.sip, "\"SIP\":\"%d.%d.%d.%d\"", (sip & 0xff000000) >> 24,
                (sip & 0x00ff0000) >> 16,
                (sip & 0x0000ff00) >> 8,
                (sip & 0x000000ff));
    }
    if (match->flags & DIP)
    {
        uint32_t dip = rte_be_to_cpu_32(match->dst_ip);
        sprintf(entryInfo->match.dip, "\"DIP\":\"%d.%d.%d.%d\"", (dip & 0xff000000) >> 24,
                (dip & 0x00ff0000) >> 16,
                (dip & 0x0000ff00) >> 8,
                (dip & 0x000000ff));
    }
    if (match->flags & TCP)
    {
        sprintf(entryInfo->match.proto, "\"proto\":\"TCP\"");
    }
    if (match->flags & UDP)
    {
        sprintf(entryInfo->match.proto, "\"proto\":\"UDP\"");
    }
    if (match->flags & ICMP)
    {
        sprintf(entryInfo->match.proto, "\"proto\":\"ICMP\"");
    }

    if (match->flags & SPORT)
    {
        sprintf(entryInfo->match.sport, "\"SPORT\":\"%d\"", rte_be_to_cpu_16(match->src_port));
    }
    if (match->flags & DPORT)
    {
        sprintf(entryInfo->match.dport, "\"DPORT\":\"%d\"", rte_be_to_cpu_16(match->dst_port));
    }

    // DOCA_LOG_INFO("match parser");
    ///////////////////////////////////////////////////Handle Action
    struct FlowQoS_ACTION *action = &(entry->action);

    if (action->flags & SIP)
    {
        uint32_t sip = rte_be_to_cpu_32(action->src_ip);
        sprintf(entryInfo->action.sip, "\"SIP\":\"%d.%d.%d.%d\"", (sip & 0xff000000) >> 24,
                (sip & 0x00ff0000) >> 16,
                (sip & 0x0000ff00) >> 8,
                (sip & 0x000000ff));
    }
    if (action->flags & DIP)
    {
        uint32_t dip = rte_be_to_cpu_32(action->dst_ip);
        sprintf(entryInfo->action.dip, "\"DIP\":\"%d.%d.%d.%d\"", (dip & 0xff000000) >> 24,
                (dip & 0x00ff0000) >> 16,
                (dip & 0x0000ff00) >> 8,
                (dip & 0x000000ff));
    }
    if (action->flags & SPORT)
    {
        sprintf(entryInfo->action.sport, "\"SPORT\":\"%d\"", rte_be_to_cpu_16(action->src_port));
    }
    if (action->flags & DPORT)
    {
        sprintf(entryInfo->action.dport, "\"DPORT\":\"%d\"", rte_be_to_cpu_16(action->dst_port));
    }
    if (action->flags & SMAC)
    {
        sprintf(entryInfo->action.smac, "\"SMAC\":\"%02x:%02x:%02x:%02x:%02x:%02x\"",
                action->src_mac[0], action->src_mac[1],
                action->src_mac[2], action->src_mac[3],
                action->src_mac[4], action->src_mac[5]);
    }
    if (action->flags & DMAC)
    {
        sprintf(entryInfo->action.dmac, "\"DMAC\":\"%02x:%02x:%02x:%02x:%02x:%02x\"",
                action->dst_mac[0], action->dst_mac[1],
                action->dst_mac[2], action->dst_mac[3],
                action->dst_mac[4], action->dst_mac[5]);
    }
    if (action->flags & TTL_DECREASE)
    {
        sprintf(entryInfo->action.ttl, "\"TTL\":\"-1\"");
    }
    // DOCA_LOG_INFO("action parser");
    ///////////////////////////////////////////////////Handle Control
    if (action->flags & COUNTER)
    {
        sprintf(entryInfo->control.counter, "\"COUNTER\":\"1\"");
    }
    if (action->flags & AGING)
    {
        sprintf(entryInfo->control.aging, "\"AGING\":\"%lu\"", entry->expireTime);
    }
    if (entry->pipe != NULL)
    {
        FlowQoS_FWD fwd[2] = {entry->pipe->matched_fwd, entry->pipe->unmatched_fwd};
        char *fwd_name[2] = {"Match", "Miss"};
        for (int i = 0; i < 2; i++)
        {
            struct FlowQoS_PIPE *pipe = (struct FlowQoS_PIPE *)fwd[i];
            switch (fwd[i])
            {
            case 0:
                sprintf(entryInfo->control.fwd[i], "\"%s\":\"%s\"", fwd_name[i], "NULL");
                break;
            case DROP:
                sprintf(entryInfo->control.fwd[i], "\"%s\":\"DROP\"", fwd_name[i]);
                break;
            case PORT:
                /* code */
                sprintf(entryInfo->control.fwd[i], "\"%s\":\"PORT\"", fwd_name[i]);
                break;
            case RSS_TO_QUEUE:
                /* code */
                sprintf(entryInfo->control.fwd[i], "\"%s\":\"RSS\"", fwd_name[i]);
                break;
            default:
                sprintf(entryInfo->control.fwd[i], "\"%s\":\"%s\"", fwd_name[i], pipe->pipeName);
                break;
            }
        }
    }
    // DOCA_LOG_INFO("FWD parser");
}

void printFlowQoSEntry(struct EntryInfo *entryInfo)
{
    char *match = (char *)(&(entryInfo->match));
    char *action = (char *)(&(entryInfo->action));
    char *control = (char *)(&(entryInfo->control));
    for (int i = 1; i < 5; i++)
    {
        if (*(match + ENTRY_INFO_ITEM_LENGTH * i) == 0)
            continue;
        char tmp[ENTRY_INFO_ITEM_LENGTH];
        sprintf(tmp, ",%s", (match + ENTRY_INFO_ITEM_LENGTH * i));
        strcat(match, tmp);
    }
    for (int i = 1; i < 7; i++)
    {
        if (*(action + ENTRY_INFO_ITEM_LENGTH * i) == 0)
            continue;
        char tmp[ENTRY_INFO_ITEM_LENGTH];
        sprintf(tmp, ",%s", (action + ENTRY_INFO_ITEM_LENGTH * i));
        strcat(action, tmp);
    }
    for (int i = 1; i < 4; i++)
    {
        if (*(control + ENTRY_INFO_ITEM_LENGTH * i) == 0)
            continue;
        char tmp[ENTRY_INFO_ITEM_LENGTH];
        sprintf(tmp, ",%s", (control + ENTRY_INFO_ITEM_LENGTH * i));
        strcat(control, tmp);
    }
    // DOCA_LOG_INFO("{\"MATCH\":{%s},"
    //               "\"ACTION\":{%s},"
    //               "\"CONTROL\":{%s}}",
    //               *match == ',' ? match + 1 : match,
    //               *action == ',' ? action + 1 : action,
    //               *control == ',' ? control + 1 : control);
    DOCA_LOG_INFO("\nMAT:[%s]\n"
                  "ACT:[%s]\n"
                  "CTL:[%s]",
                  *match == ',' ? match + 1 : match,
                  *action == ',' ? action + 1 : action,
                  *control == ',' ? control + 1 : control);
};

void printFlowQoSEntryToCmdline(struct EntryInfo *entryInfo)
{
    char *match = (char *)(&(entryInfo->match));
    char *action = (char *)(&(entryInfo->action));
    char *control = (char *)(&(entryInfo->control));
    for (int i = 1; i < 5; i++)
    {
        if (*(match + ENTRY_INFO_ITEM_LENGTH * i) == 0)
            continue;
        char tmp[ENTRY_INFO_ITEM_LENGTH];
        sprintf(tmp, ",%s", (match + ENTRY_INFO_ITEM_LENGTH * i));
        strcat(match, tmp);
    }
    for (int i = 1; i < 7; i++)
    {
        if (*(action + ENTRY_INFO_ITEM_LENGTH * i) == 0)
            continue;
        char tmp[ENTRY_INFO_ITEM_LENGTH];
        sprintf(tmp, ",%s", (action + ENTRY_INFO_ITEM_LENGTH * i));
        strcat(action, tmp);
    }
    for (int i = 1; i < 4; i++)
    {
        if (*(control + ENTRY_INFO_ITEM_LENGTH * i) == 0)
            continue;
        char tmp[ENTRY_INFO_ITEM_LENGTH];
        sprintf(tmp, ",%s", (control + ENTRY_INFO_ITEM_LENGTH * i));
        strcat(control, tmp);
    }
    cmdline_printf(flowQoS_getCmd(), "MAT:[%s]\n"
                                     "ACT:[%s]\n"
                                     "CTL:[%s]\n\n",
                   *match == ',' ? match + 1 : match,
                   *action == ',' ? action + 1 : action,
                   *control == ',' ? control + 1 : control);
};

void printFlowQoSPipe(struct FlowQoS_PIPE *flowQoS_pipe)
{
    struct FlowQoS_ENTRY entry = {0};
    struct EntryInfo entryInfo = {0};
    entry.pipe = flowQoS_pipe;
    entry.match = flowQoS_pipe->match_pattern;
    entry.action = flowQoS_pipe->action_pattern;
    dumpFlowQoSEntry(&entry, &entryInfo);
    DOCA_LOG_INFO("<==========FlowQoS_PIPE INFO=============>");
    DOCA_LOG_INFO("NAME:%s Capacity:%d", flowQoS_pipe->pipeName, flowQoS_pipe->max_entry_amount);
    printFlowQoSEntry(&entryInfo);
    DOCA_LOG_INFO("<==========FlowQoS_PIPE INFO=============>");
}

/**********************************************************/

/**
 * @brief cmd from pipe module
 * 
 */
struct cmd_dumpFDB
{
    cmdline_fixed_string_t cmd;
};

static void cmd_dumpFDB_parsed(__rte_unused void *parsed_result,
                               struct cmdline *cl,
                               __rte_unused void *data)
{
    dumpFDB();
}

cmdline_parse_token_string_t cmd_dumpFDB_cmd =
    TOKEN_STRING_INITIALIZER(struct cmd_dumpFDB, cmd, "dumpFDB");

cmdline_parse_inst_t cmd_dumpFDB_obj = {
    .f = cmd_dumpFDB_parsed, /* function to call */
    .data = NULL,            /* 2nd arg of func */
    .help_str = "Output DOCA-PIPE info and offloaded entry",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&cmd_dumpFDB_cmd,
        NULL,
    },
};

void registerPipeCmd()
{
    static bool cmdRegistered = false;
    if (!cmdRegistered)
    {
        flowQoS_registCmd(&cmd_dumpFDB_obj);
        cmdRegistered = true;
        DOCA_LOG_INFO("Register dumpFDB cmd");
    }
}
