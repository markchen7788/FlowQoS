/**
 * @file flowQoS_timer.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief software timer based on timing wheel
 * @version 0.1
 * @date 2024-01-22
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <doca_log.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include "flowQoS_timer.h"
#include "flowQoS_worker.h"
DOCA_LOG_REGISTER(FLOWQOS_TIMER);

RTE_DEFINE_PER_LCORE(flowQoS_timer_mgr *, timer_mgr); ///< threadLocal:each lcore has its own timer_mgr
#define TIMER_MGR RTE_PER_LCORE(timer_mgr)

uint64_t GAP = 0; ///< the interval between 2 tick
/**
 * @brief init timer_mgr
 * 
 * @param dummy 
 * @return int 
 */
int flowQoS_timer_mgr_init(__rte_unused void *dummy)
{
    TIMER_MGR = (flowQoS_timer_mgr *)rte_malloc(NULL, sizeof(flowQoS_timer_mgr), 0);
    if (TIMER_MGR == NULL)
    {
        DOCA_LOG_ERR("%d Allocate Timer Mgr Fail", rte_lcore_id());
        return -1;
    }
    memset(TIMER_MGR, 0, sizeof(flowQoS_timer_mgr));
    TIMER_MGR->timeout = 0;
    TIMER_MGR->startStmp = rte_rdtsc();
    for (int i = 0; i < TIMER_WHEEL_COUNT; ++i)
    {
        flowQoS_timer_wheel *wheel = &TIMER_MGR->wheels[i];
        for (int j = 0; j < TIMER_BUCKET_COUNT; ++j)
        {
            flowQoS_timer *bucket = &wheel->buckets[j];
            bucket->prev = bucket->next = bucket;
        }
    }
    return 0;
}

// timeout: first trigger time
// repeat:  loop interval time after first trigger
int timer_start(flowQoS_timer_mgr *timer_mgr, flowQoS_timer *timer, flowQoS_timer_cb cb, void *args, uint64_t timeout, uint64_t repeat)
{
    if (NULL == cb || TIMER_MAX_TIMEOUT < timeout)
    {
        return -1;
    }
    uint64_t clamped_timeout = timer_mgr->timeout + timeout;
    if (clamped_timeout < timeout)
    {
        clamped_timeout = (uint64_t)~0;
    }
    timer->cb = cb;
    timer->cb_args = args;
    timer->timeout = clamped_timeout;
    timer->repeat = repeat;

    int widx = 0, cur = TIMER_WHEEL_CUR_INDEX(0),
        bidx = timeout % TIMER_BUCKET_COUNT;
    while (timeout >= TIMER_BUCKET_COUNT)
    {
        widx += 1;
        timeout >>= TIMER_WHEEL_BITS;
        bidx = timeout % TIMER_BUCKET_COUNT;
        cur = TIMER_WHEEL_CUR_INDEX(widx);
    }
    if (TIMER_WHEEL_COUNT <= widx)
    {
        return -2;
    }
    flowQoS_timer_wheel *wheel = &timer_mgr->wheels[widx];
    flowQoS_timer *bucket = &wheel->buckets[(cur + bidx) % TIMER_BUCKET_COUNT];
    timer->prev = bucket->prev;
    timer->next = bucket;
    timer->prev->next = timer;
    bucket->prev = timer;
    return 0;
}

int timer_stop(flowQoS_timer *timer)
{
    if (timer->prev && timer->next)
    {
        timer->prev->next = timer->next;
        timer->next->prev = timer->prev;
        timer->prev = timer->next = NULL;
    }
    return 0;
}

int timer_again(flowQoS_timer_mgr *timer_mgr, flowQoS_timer *timer)
{
    if (NULL == timer->cb)
    {
        return -1;
    }
    if (timer->repeat)
    {
        timer_stop(timer);
        timer_start(timer_mgr, timer, timer->cb, timer->cb_args, timer->repeat, timer->repeat);
    }
    return 0;
}

int timer_reset(flowQoS_timer_mgr *timer_mgr, flowQoS_timer *timer, uint64_t timeout)
{
    if (NULL == timer->cb)
    {
        return -1;
    }
    timer_stop(timer);
    timer_start(timer_mgr, timer, timer->cb, timer->cb_args, timeout, 0);
    return 0;
}

int timer_cascade(flowQoS_timer_mgr *timer_mgr, int widx, int bidx)
{
    flowQoS_timer_wheel *wheel = &timer_mgr->wheels[widx];
    flowQoS_timer *bucket = &wheel->buckets[bidx];
    flowQoS_timer *timer = bucket->next;
    while (timer != bucket)
    {
        flowQoS_timer *next = timer->next;
        assert(timer->timeout >= timer_mgr->timeout);
        uint64_t timeout = timer->timeout - timer_mgr->timeout;
        // reinsert
        timer_stop(timer);
        timer_start(timer_mgr, timer, timer->cb, timer->cb_args, timeout, timer->repeat);
        timer = next;
    }
    return bidx;
}

int timer_tick(flowQoS_timer_mgr *timer_mgr)
{
    int res = 0;
    int bidx = timer_mgr->timeout % TIMER_BUCKET_COUNT;
    if (!bidx)
    {
        int widx = 1;
        while (
            widx < TIMER_WHEEL_COUNT &&
            !timer_cascade(timer_mgr, widx, TIMER_WHEEL_CUR_INDEX(widx)))
        {
            ++widx;
        }
    }
    flowQoS_timer *bucket = &timer_mgr->wheels[0].buckets[bidx];
    flowQoS_timer *timer = bucket->next;
    while (timer != bucket)
    {
        flowQoS_timer *next = timer->next;
        timer_stop(timer);
        timer_again(timer_mgr, timer);
        timer->cb(timer);
        timer = next;
        res++;
    }
    ++timer_mgr->timeout;
    return res;
}

int _flowQoS_timer_tick(int cid)
{
    return flowQoS_timer_tick();
}

void flowQoS_timer_init()
{
    unsigned lcore_id;
    /* call lcore_hello() on every slave lcore */
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        rte_eal_remote_launch(flowQoS_timer_mgr_init, NULL, lcore_id);
        rte_eal_wait_lcore(lcore_id);
    }
    GAP = rte_get_tsc_hz() / TIMER_FREQUENCY;
    register_general_processor(_flowQoS_timer_tick, "Timer");
    DOCA_LOG_INFO("FlowQoS Timer init");
}

int flowQoS_timer_tick()
{
    if (TIMER_MGR->startStmp + TIMER_MGR->timeout * GAP < rte_rdtsc())
    {
        return timer_tick(TIMER_MGR);
    }
    return 0;
}

int flowQoS_timer_add(flowQoS_timer *timer, flowQoS_timer_cb cb, void *args, uint64_t timeout)
{
    return timer_start(TIMER_MGR, timer, cb, args, timeout, 0);
}

void flowQoS_timer_del(flowQoS_timer *timer)
{
    timer_stop(timer);
}

int flowQoS_timer_reset(flowQoS_timer *timer, uint64_t timeout)
{
    return timer_reset(TIMER_MGR, timer, timeout);
}