/**
 * @file flowQoS_message.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief lockless message API for communication between master core and slave cores
 * @version 0.1
 * @date 2024-01-20
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <rte_spinlock.h>
#include <doca_log.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include "flowQoS_message.h"
#include "flowQoS_worker.h"

DOCA_LOG_REGISTER(FLOWQOS_MESSAGE);

#define MAX_RING_COUNT 8                         ///< maximum messages in rte_ring
#define MESSAGE_MAX_SIZE 1024                    ///< maximum length of message
rte_spinlock_t flowQoS_message_lock;             ///< spinlock for printing logs
struct rte_mempool *FlowQoS_MESSAGE_POOL = NULL; ///< message pool
/**
 * @brief task struct for flowQoS_message_multiThread_do() API when sending tasks from master to slaves
 * 
 */
struct FlowQoS_syn_task
{
    flowQoS_message_cb cb;
    void *args;
};
/**
 * @brief each slave core has one ring for sending message to master and has one ring for receiving message from master
 * 
 */
struct flowQoS_core_socket
{
    /* data */
    struct rte_ring *master_to_slave_ring;
    struct rte_ring *slave_to_master_ring;
};

struct flowQoS_core_socket socks[8];
/**
 * @brief debug api for checking count of rte_ring
 * 
 */
void flowQoS_message_debug()
{
    unsigned lcore_id = 0;
    DOCA_LOG_INFO("Message Pool In Use:%d", rte_mempool_in_use_count(FlowQoS_MESSAGE_POOL));
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        DOCA_LOG_INFO("Core %d:[master-to-slave-ring:%d,slave-to-master-ring:%d]", lcore_id, rte_ring_count(socks[lcore_id].master_to_slave_ring), rte_ring_count(socks[lcore_id].slave_to_master_ring));
    }
}
/**
 * @brief copy msg to the memory in mempool
 * 
 * @param msg 
 * @param len 
 * @return void* 
 */
void *flowQoS_make_msg(void *msg, int len)
{
    void *res;
    if (len > MESSAGE_MAX_SIZE)
    {
        DOCA_LOG_ERR("Msg is too long");
        return NULL;
    }
    if (rte_mempool_get(FlowQoS_MESSAGE_POOL, &res) != 0)
    {
        DOCA_LOG_ERR("Make msg fail");
        return NULL;
    }
    rte_memcpy(res, msg, len);
    return res;
}

/**
 * @brief put back msg mem to mempool 
 * 
 * @param msg 
 */
void flowQoS_free_msg(void *msg)
{
    rte_mempool_put(FlowQoS_MESSAGE_POOL, msg);
}

/**
 * @brief unicast send
 * 
 * @param _msg 
 * @param len 
 * @param target_core slave core id 
 * @param is_request sending from master to target slave core if true and sending from target slave core to master if false 
 * @return int return 1 if succeed
 */
int flowQoS_send_msg(void *_msg, int len, unsigned target_core, bool is_request)
{
    void *msg = flowQoS_make_msg(_msg, len);
    if (msg != NULL)
    {
        int ret = 0;
        if (is_request)
            ret = rte_ring_enqueue(socks[target_core].master_to_slave_ring, msg);
        else
            ret = rte_ring_enqueue(socks[target_core].slave_to_master_ring, msg);
        if (ret != 0)
        {
            flowQoS_free_msg(msg);
            DOCA_LOG_ERR("Core %d Send msg to Core %d fail for full tx", rte_lcore_id(), target_core);
            return 0;
        }
    }
    else
    {
        DOCA_LOG_ERR("Core %d Send msg to Core %d fail for empty pool", rte_lcore_id(), target_core);
        return 0;
    }
    return 1;
}
/**
 * @brief unicast recv
 * 
 * @param msg_buf 
 * @param len 
 * @param target_core slave core id 
 * @param is_request receiving from master to target slave core if true and receiving from target slave core to master if false
 * @return int return 1 if succeed
 */
int flowQoS_recv_msg(void *msg_buf, int len, unsigned target_core, bool is_request)
{
    void *_msg;
    if (msg_buf != NULL)
    {
        int ret = 0;
        if (is_request)
            ret = rte_ring_dequeue(socks[target_core].master_to_slave_ring, &_msg);
        else
            ret = rte_ring_dequeue(socks[target_core].slave_to_master_ring, &_msg);
        if (ret != 0)
        {
            return 0;
        }

        if (len > MESSAGE_MAX_SIZE)
            len = MESSAGE_MAX_SIZE;

        rte_memcpy(msg_buf, _msg, len);
        flowQoS_free_msg(_msg);
    }
    else
    {
        DOCA_LOG_ERR("Core %d recv msg from Core %d fail for empty msg buf", rte_lcore_id(), target_core);
        return 0;
    }
    return 1;
}

int flowQoS_message_multicast_send(void *msg, int len)
{
    int cid = rte_lcore_id();
    int res = 0;
    if (cid == rte_get_main_lcore())
    {
        unsigned lcore_id;
        RTE_LCORE_FOREACH_WORKER(lcore_id)
        {

            res += flowQoS_send_msg(msg, len, lcore_id, true);
        }
        return res;
    }
    else
    {
        return flowQoS_send_msg(msg, len, cid, false);
    }
}

int flowQoS_message_multicast_recv(void *msg_arr, int msg_len)
{
    int cid = rte_lcore_id();
    int res = 0;
    if (cid == rte_get_main_lcore())
    {
        unsigned lcore_id;
        RTE_LCORE_FOREACH_WORKER(lcore_id)
        {
            int count = 0;
            while (flowQoS_recv_msg(msg_arr, msg_len, lcore_id, false) == 0)
            {
                rte_delay_ms(10);
                count++;
                if (count == 300)
                {
                    res--;
                    break;
                }
            }
            res++;
            msg_arr = msg_arr + msg_len;
        }
        return res;
    }
    else
    {
        return flowQoS_recv_msg(msg_arr, msg_len, cid, true);
    }
}
void FlowQoS_SYN_PRINT(const char *format, ...)
{
    va_list args;
    char temp[4096];
    va_start(args, format);
    vsprintf(temp, format, args);
    rte_spinlock_lock(&flowQoS_message_lock);
    DOCA_LOG_INFO("Core %d:%s", rte_lcore_id(), temp);
    rte_spinlock_unlock(&flowQoS_message_lock);
}

/**
 * @brief test slave func 
 * 
 * @param dummy 
 * @return int 
 */
int slave(__rte_unused void *dummy)
{
    char buf[100];
    int count = 0;
    while (flowQoS_message_multicast_recv((void *)buf, 100) == 0)
    {
        rte_delay_ms(10);
        count++;
        if (count == 100)
        {
            return 0;
        }
    }
    FlowQoS_SYN_PRINT("Core %d recv:%s", rte_lcore_id(), buf);
    sprintf(buf, "Slave %d recv sucesss", rte_lcore_id());
    flowQoS_message_multicast_send((void *)buf, 100);
    return 0;
}

/**
 * @brief slave func running in slave cores of flowQoS_message_multiThread_do API, which is registered into flowQoS wortker module.
 * 
 * @param cid 
 * @return int 
 */
int flowQoS_message_multiThread_do_slave(int cid)
{
    struct FlowQoS_syn_task task;
    if (flowQoS_message_multicast_recv((void *)&task, sizeof(task)))
    {
        task.cb(task.args);
        int ret = 1;
        flowQoS_message_multicast_send((void *)(&ret), sizeof(ret));
        return 1;
    }
    return 0;
}

int flowQoS_message_multiThread_do(flowQoS_message_cb cb, void *args) // args is only for read
{
    struct FlowQoS_syn_task task = {.cb = cb, .args = args};
    flowQoS_message_multicast_send((void *)&task, sizeof(task));
    int res = 0;
    int ret = flowQoS_message_multicast_recv((void *)(&res), sizeof(res));
    if (ret == rte_lcore_count() - 1)
    {
        return 1;
    }
    else
    {
        DOCA_LOG_ERR("flowQoS_message_multiThread_do ERR for not recv all slaves' reply");
        return 0;
    }
}

void flowQoS_message_test()
{
    flowQoS_message_debug();
    rte_eal_mp_remote_launch(slave, NULL, SKIP_MAIN);
    char buf[800];
    sprintf(buf, "Hello,I am master core");
    int ret = flowQoS_message_multicast_send(buf, 100);
    FlowQoS_SYN_PRINT("Master Send %d mesg", ret);
    ret = flowQoS_message_multicast_recv(buf, 100);
    FlowQoS_SYN_PRINT("Master recv %d mesg", ret);
    for (int i = 0; i < ret; i++)
    {

        DOCA_LOG_INFO("%s", buf + 100 * i);
    }
    rte_eal_mp_wait_lcore();
    flowQoS_message_debug();
}

int flowQoS_message_init()
{
    if (FlowQoS_MESSAGE_POOL == NULL)
    {
        rte_spinlock_init(&flowQoS_message_lock);
        unsigned lcore_id;
        char ringName[20];
        RTE_LCORE_FOREACH_WORKER(lcore_id)
        {
            sprintf(ringName, "Core%d-RX", lcore_id);
            socks[lcore_id].slave_to_master_ring = rte_ring_create(ringName, MAX_RING_COUNT, rte_socket_id(), 0);
            sprintf(ringName, "Core%d-TX", lcore_id);
            socks[lcore_id].master_to_slave_ring = rte_ring_create(ringName, MAX_RING_COUNT, rte_socket_id(), 0);

            if (socks[lcore_id].slave_to_master_ring == NULL || socks[lcore_id].master_to_slave_ring == NULL)
            {
                DOCA_LOG_ERR("Core %d Create Socket Fail......", lcore_id);
                return 0;
            }
            else
                DOCA_LOG_INFO("Core %d Create Socket Success......", lcore_id);
        }

        FlowQoS_MESSAGE_POOL = rte_mempool_create("Message_POOL", (8 /*Max Arm Cores*/ - 1) * 2 * MAX_RING_COUNT,
                                                  MESSAGE_MAX_SIZE, 32, 0,
                                                  NULL, NULL, NULL, NULL,
                                                  rte_socket_id(), 0);

        if (!FlowQoS_MESSAGE_POOL)
        {
            DOCA_LOG_ERR("Create Message Pool fail!");
            return 0;
        }
        else
            DOCA_LOG_INFO("Create Message Pool success");

        flowQoS_message_test();
        register_general_processor(flowQoS_message_multiThread_do_slave, "Message");
        DOCA_LOG_INFO("register_general_processor flowQoS_message_multiThread_do_slave");
    }
    else
    {
        DOCA_LOG_INFO("FlowQoS_message init already");
        return 0;
    }
    return 1;
}
