/**
 * @file flowQoS_timer.h
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief software timer based on timing wheel
 * @version 0.1
 * @date 2024-01-22
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef FLOWQOS_TIMER_H_
#define FLOWQOS_TIMER_H_

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#define TIMER_FREQUENCY 1000 // Tick Every 1 ms,timeout unit is 1ms
#define TIMER_WHEEL_COUNT 2
#define TIMER_WHEEL_BITS 18
#define TIMER_BUCKET_COUNT (1 << TIMER_WHEEL_BITS)
#define TIMER_WHEEL_CUR_INDEX(_n) \
    ((timer_mgr->timeout >> TIMER_WHEEL_BITS * (_n)) % TIMER_BUCKET_COUNT)
#define TIMER_MAX_TIMEOUT \
    (((uint64_t)1 << (TIMER_WHEEL_COUNT * TIMER_WHEEL_BITS)) - 1)

typedef struct flowQoS_timer_s flowQoS_timer;
typedef struct flowQoS_timer_mgr_s flowQoS_timer_mgr;
typedef void (*flowQoS_timer_cb)(flowQoS_timer *timer);
struct flowQoS_timer_s
{
    flowQoS_timer_cb cb; ///< callback of timer
    void *cb_args;       ///< callback args
    uint64_t timeout;
    uint64_t repeat;
    struct flowQoS_timer_s *prev, *next; ///< link of timer on timer wheel
};

typedef struct
{
    flowQoS_timer buckets[TIMER_BUCKET_COUNT];
} flowQoS_timer_wheel;

struct flowQoS_timer_mgr_s
{
    uint64_t startStmp;
    uint64_t timeout;
    flowQoS_timer_wheel wheels[TIMER_WHEEL_COUNT];
};

/**
 * @brief init timer wheel
 * 
 */
void flowQoS_timer_init();
/**
 * @brief drive timer wheel every 1ms
 * 
 * @return int 
 */
int flowQoS_timer_tick();
/**
 * @brief add a timer
 * 
 * @param timer 
 * @param cb 
 * @param args 
 * @param timeout unit is [s]
 * @return int 
 */
int flowQoS_timer_add(flowQoS_timer *timer, flowQoS_timer_cb cb, void *args, uint64_t timeout); // timeout unit is ms
/**
 * @brief del a timer
 * 
 * @param timer 
 */
void flowQoS_timer_del(flowQoS_timer *timer);
/**
 * @brief reset this timer
 * 
 * @param timer 
 * @param timeout 
 * @return int 
 */
int flowQoS_timer_reset(flowQoS_timer *timer, uint64_t timeout);

#endif /* FLOWQOS_TIMER_H_ */
