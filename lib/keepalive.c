/*
 * Copyright (c) 2017 Intel, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "keepalive.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "seq.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(keepalive);

static bool keepalive_enable = false;      /* Keepalive disabled by default. */
static uint32_t keepalive_timer_interval;  /* keepalive timer interval. */
static struct keepalive_info ka_info;

/* Returns true if keepalive is enabled, false otherwise. */
bool
ka_is_enabled(void)
{
    return keepalive_enable;
}

/* Finds the thread by 'tid' in 'process_list' map and update
 * the thread state and last_seen_time stamp.  This is invoked
 * periodically(based on keepalive-interval) as part of callback
 * function in the context of keepalive thread.
 */
static void
ka_set_thread_state_ts(pid_t tid, enum keepalive_state state,
                       uint64_t last_alive)
{
    struct ka_process_info *pinfo;

    ovs_mutex_lock(&ka_info.proclist_mutex);
    HMAP_FOR_EACH_WITH_HASH (pinfo, node, hash_int(tid, 0),
                             &ka_info.process_list) {
        if (pinfo->tid == tid) {
            pinfo->state = state;
            pinfo->last_seen_time = last_alive;
        }
    }
    ovs_mutex_unlock(&ka_info.proclist_mutex);
}

/* Retrieve and return the keepalive timer interval from OVSDB. */
static uint32_t
ka_get_timer_interval(const struct smap *ovs_other_config)
{
    uint32_t ka_interval;

    /* Timer granularity in milliseconds
     * Defaults to OVS_KEEPALIVE_TIMEOUT(ms) if not set */
    ka_interval = smap_get_int(ovs_other_config, "keepalive-interval",
                               OVS_KEEPALIVE_DEFAULT_TIMEOUT);

    VLOG_INFO("Keepalive timer interval set to %"PRIu32" (ms)\n", ka_interval);
    return ka_interval;
}

/* Invoke periodically to update the status and last seen timestamp
 * of the thread in to 'process_list' map. Runs in the context of
 * keepalive thread.
 */
static void
ka_update_thread_state(pid_t tid, const enum keepalive_state state,
                       uint64_t last_alive)
{
    switch (state) {
    case KA_STATE_ALIVE:
    case KA_STATE_MISSING:
        ka_set_thread_state_ts(tid, KA_STATE_ALIVE, last_alive);
        break;
    case KA_STATE_UNUSED:
    case KA_STATE_SLEEP:
    case KA_STATE_DEAD:
    case KA_STATE_GONE:
        ka_set_thread_state_ts(tid, state, last_alive);
        break;
    default:
        OVS_NOT_REACHED();
    }
}

/* Register relay callback function. */
static void
ka_register_relay_cb(ka_relay_cb cb, void *aux)
{
    ka_info.relay_cb = cb;
    ka_info.relay_cb_data = aux;
}

void
ka_init(const struct smap *ovs_other_config)
{
    if (smap_get_bool(ovs_other_config, "enable-keepalive", false)) {
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once_enable)) {
            keepalive_enable =  true;
            VLOG_INFO("OvS Keepalive enabled.");

            keepalive_timer_interval =
                ka_get_timer_interval(ovs_other_config);

            ka_register_relay_cb(ka_update_thread_state, NULL);
            ovs_mutex_init(&ka_info.proclist_mutex);
            hmap_init(&ka_info.process_list);

            ka_info.init_time = time_wall_msec();

            ovsthread_once_done(&once_enable);
        }
    }
}

void
ka_destroy(void)
{
    if (!ka_is_enabled()) {
       return;
    }

    ovs_mutex_lock(&ka_info.proclist_mutex);
    struct ka_process_info *pinfo;
    HMAP_FOR_EACH_POP (pinfo, node, &ka_info.process_list) {
        free(pinfo);
    }
    ovs_mutex_unlock(&ka_info.proclist_mutex);

    hmap_destroy(&ka_info.process_list);
    ovs_mutex_destroy(&ka_info.proclist_mutex);
}
