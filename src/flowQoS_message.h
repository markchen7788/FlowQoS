/**
 * @file flowQoS_message.h
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief lockless message API for communication between master core and slave cores
 * @version 0.1
 * @date 2024-01-20
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef FLOWQOS_MESSAGE_H_
#define FLOWQOS_MESSAGE_H_
/**
 * @brief tasks done by slave cores 
 * 
 */
typedef void (*flowQoS_message_cb)(void *args);
/**
 * @brief init message module
 * 
 * @return int 
 */
int flowQoS_message_init();
/**
 * @brief synchronous print function to avoid multi-threads printing info in a blur 
 * 
 * @param format 
 * @param ... 
 */
void FlowQoS_SYN_PRINT(const char *format, ...);
/**
 * @brief test message api
 * 
 */
void flowQoS_message_test();
/**
 * @brief master core sends task to slaves through rte_ring and waits for the task being finished.Usually slaves write different memory to avoid synchronizing.
 * 
 * @param cb task func
 * @param args task arguments
 * @return int return 1 if succeed
 */
int flowQoS_message_multiThread_do(flowQoS_message_cb cb, void *args);
/**
 * @brief send message from master to slaves or slaves to master.
 * 
 * @param msg msg buffer
 * @param len msg len
 * @return int return 1 if succeed
 */
int flowQoS_message_multicast_send(void *msg, int len);
/**
 * @brief receive message from master to slaves or slaves to master.
 * 
 * @param msg_arr master should prepare enough memory(len*slaveCoreNum) to store replys from slaves.
 * @param msg_len msg len
 * @return int return 1 if succeed
 */
int flowQoS_message_multicast_recv(void *msg_arr, int msg_len);
#endif /* FLOWQOS_MESSAGE_H_ */
