/**
 * @file flowQoS_pipe.h
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief encapsulation of doca-flow API
 * @version 0.1
 * @date 2024-01-21
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef FLOWQOS_PIPE_H_
#define FLOWQOS_PIPE_H_
#include <doca_flow.h>
#include <sys/queue.h>
#include <rte_common.h>

#define SMAC 1 << 0          ///< used in FlowQoS_ENTRY and FlowQoS_PIPE: match src mac or modify src mac
#define DMAC 1 << 1          ///< used in FlowQoS_ENTRY and FlowQoS_PIPE: match dst mac or modify dst mac
#define SIP 1 << 2           ///< used in FlowQoS_ENTRY and FlowQoS_PIPE: match src ip or modify src ip
#define DIP 1 << 3           ///< used in FlowQoS_ENTRY and FlowQoS_PIPE: match dst ip or modify dst ip
#define ICMP 1 << 4          ///< reserved flag for icmp, currently it's useless
#define TCP 1 << 5           ///< used in FlowQoS_ENTRY and FlowQoS_PIPE: match TCP
#define UDP 1 << 6           ///< used in FlowQoS_ENTRY and FlowQoS_PIPE: match UDP
#define SPORT 1 << 7         ///< used in FlowQoS_ENTRY and FlowQoS_PIPE: match src port or modify src port
#define DPORT 1 << 8         ///< used in FlowQoS_ENTRY and FlowQoS_PIPE: match dst port or modify dst port
#define TTL_DECREASE 1 << 9  ///< used in FlowQoS_PIPE: decrease ttl
#define AGING 1 << 10        ///< used in FlowQoS_ENTRY and FlowQoS_PIPE: enable aging
#define COUNTER 1 << 11      ///< used in FlowQoS_PIPE: enable counter
#define DROP 1 << 12         ///< used in FlowQoS_PIPE: drop flow
#define PORT 1 << 13         ///< used in FlowQoS_PIPE: fwd to port
#define RSS_TO_QUEUE 1 << 14 ///< used in FlowQoS_PIPE: fwd to arm
#define IS_ROOT true         ///< used in FlowQoS_PIPE: is root pipe

#define MAX_AGED_CT_PER_POLL 256  ///< maximum aged doca-flow entry per polling
#define ENTRY_INFO_ITEM_LENGTH 32 ///< maximum length of item in entry after being transformed into string

#define BE_IPV4_ADDR(a, b, c, d) (RTE_BE32(((uint32_t)a << 24) + (b << 16) + (c << 8) + d)) ///< create IPV4 address
#define SET_MAC_ADDR(addr, a, b, c, d, e, f) \
    do                                       \
    {                                        \
        addr[0] = a & 0xff;                  \
        addr[1] = b & 0xff;                  \
        addr[2] = c & 0xff;                  \
        addr[3] = d & 0xff;                  \
        addr[4] = e & 0xff;                  \
        addr[5] = f & 0xff;                  \
    } while (0)                    ///< create source mac address
#define DEFAULT_TIMEOUT_US (10000) ///< default timeout for processing entries
#define NB_ACTIONS_ARR (1)         ///< default action number in doca-flow entry

typedef uint64_t FlowQoS_FWD;                    ///< fwd type of doca-flow pipe.(PORT,RSS_TO_QUEUE,DROP or next_pipe pointer)
typedef void (*FlowQoS_Aging_Callback)(void *);  ///< user_defined callback when aging a doca-flow entry
typedef void (*FlowQoS_QoS_Handler)(void *args); ///< user_defined callback when flowQoS module offload a flow

struct FlowQoS_MATCH
{
    uint64_t flags;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t proto;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t rss; ///< rss val obtained from rte_mbuf
} __rte_cache_aligned;
struct FlowQoS_ACTION
{
    uint64_t flags;
    uint8_t src_mac[DOCA_ETHER_ADDR_LEN];
    uint8_t dst_mac[DOCA_ETHER_ADDR_LEN];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
} __rte_cache_aligned;

/**
 * @brief FlowQoS_PIPE is similer to doca-flow pipe but simplify building pipe.
 *
 */
struct FlowQoS_PIPE
{
    struct doca_flow_port *src_doca_port;
    struct doca_flow_port *dst_doca_port;
    struct doca_flow_pipe *doca_pipe;
    struct FlowQoS_MATCH match_pattern;
    struct FlowQoS_ACTION action_pattern;
    FlowQoS_FWD matched_fwd;
    FlowQoS_FWD unmatched_fwd;
    int max_entry_amount;
    int port_id;
    char pipeName[30];
    bool is_root;
} __rte_cache_aligned;

/**
 * @brief FlowQoS_ENTRY is similar to doca-flow entry.
 *
 */
struct FlowQoS_ENTRY
{
    struct FlowQoS_MATCH match;
    struct FlowQoS_ACTION action;
    struct doca_flow_pipe_entry *entry;
    struct FlowQoS_PIPE *pipe;
    uint64_t expireTime;
    /**************Aging Callback*******************/
    FlowQoS_Aging_Callback cb;
    void *cb_args;
    /**************FlowQoS_callback*****************/
    uint64_t priority;                      /// flowQoS priority, entry has higher priority will be offloaded earlier than entry with lower priority
    TAILQ_ENTRY(FlowQoS_ENTRY) index;       ///< tailQ used to implement fifo queue containing new entry
    FlowQoS_QoS_Handler flowQoS_qosHandler; ///< callback func revoked when flowQoS offloading a new flow
    void *flowQoS_args;                     ///< args of flowQoS_qosHandler
} __rte_cache_aligned;

/**
 * @brief struct for storing transformed flowQoS_entry, all attributes in flowQoS_ENTRY has been transformed to string.
 * 
 */
struct EntryInfo 
{
    struct Match
    {
        char sip[ENTRY_INFO_ITEM_LENGTH];
        char dip[ENTRY_INFO_ITEM_LENGTH];
        char proto[ENTRY_INFO_ITEM_LENGTH];
        char sport[ENTRY_INFO_ITEM_LENGTH];
        char dport[ENTRY_INFO_ITEM_LENGTH];
    } match;
    struct Action
    {
        char sip[ENTRY_INFO_ITEM_LENGTH];
        char dip[ENTRY_INFO_ITEM_LENGTH];
        char sport[ENTRY_INFO_ITEM_LENGTH];
        char dport[ENTRY_INFO_ITEM_LENGTH];
        char smac[ENTRY_INFO_ITEM_LENGTH];
        char dmac[ENTRY_INFO_ITEM_LENGTH];
        char ttl[ENTRY_INFO_ITEM_LENGTH];
    } action;
    struct Control
    {
        char counter[ENTRY_INFO_ITEM_LENGTH];
        char aging[ENTRY_INFO_ITEM_LENGTH];
        char fwd[ENTRY_INFO_ITEM_LENGTH][ENTRY_INFO_ITEM_LENGTH];
    } control;
};
/**
 * @brief dump doca-flow FDB
 * 
 */
void dumpFDB();
/**
 * @brief build a FlowQoS_PIPE
 * 
 * @param port_id 
 * @param pipe_name 
 * @param matchFlags eg: SIP|DIP|SPORT|DPORT|TCP
 * @param actionFlags eg: DIP|DMAC|TTL_DECREASE|AGING
 * @param matched eg: PORT
 * @param unmatched eg: RSS_TO_QUEUE
 * @param is_root eg: IS_ROOT
 * @param entryAmount eg:1<10
 * @return struct FlowQoS_PIPE* 
 */
struct FlowQoS_PIPE *flowQoS_build_pipe(int port_id, char *pipe_name,
                                        uint64_t matchFlags, uint64_t actionFlags,
                                        FlowQoS_FWD matched, FlowQoS_FWD unmatched,
                                        bool is_root, int entryAmount);
/**
 * @brief add a flowQoS_ENTRY 
 * 
 * @param flowQoS_pipe 
 * @param entry should fill right values according to pipe
 * @param flowQueueId doca-flow queue id, we run doca-flow in vnf mode and don't enable hws cause it not support multi-threads. 
 * @param flush add flow immediately(doca_flow_flags_type:DOCA_FLOW_NO_WAIT) if flush==1, add flow later(doca_flow_flags_type:DOCA_FLOW_WAIT_FOR_BATCH) if flush==0 and add n flows(doca_flow_flags_type:DOCA_FLOW_WAIT_FOR_BATCH) in flowQueue if flush==n(n>1)
 * @return int 
 */
int flowQoS_add_entry(struct FlowQoS_PIPE *flowQoS_pipe, struct FlowQoS_ENTRY *entry, int flowQueueId, int flush);
/**
 * @brief remove aged doca-flow entry and revoke callback
 * 
 * @param port_id 
 * @param flowQueueId 
 * @return int 
 */
int flowQoS_aging_handle(int port_id, int flowQueueId);
/**
 * @brief transform FlowQoS_ENTRY into EntryInfo in order to print onto cmdline
 * 
 * @param entry 
 * @param entryInfo 
 */
void dumpFlowQoSEntry(struct FlowQoS_ENTRY *entry, struct EntryInfo *entryInfo);
/**
 * @brief print EntryInfo into doca logs
 * 
 * @param entryInfo 
 */
void printFlowQoSEntry(struct EntryInfo *entryInfo);
/**
 * @brief print EntryInfo into dpdk cmdlines
 * 
 * @param entryInfo 
 */
void printFlowQoSEntryToCmdline(struct EntryInfo *entryInfo);
/**
 * @brief print info of flowQoS_PIPE 
 * 
 * @param flowQoS_pipe 
 */
void printFlowQoSPipe(struct FlowQoS_PIPE *flowQoS_pipe);

#endif /* FLOWQOS_PIPE_H_ */