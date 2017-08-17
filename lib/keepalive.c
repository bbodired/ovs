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
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "process.h"
#include "seq.h"
#include "timeval.h"
#include "unixctl.h"

VLOG_DEFINE_THIS_MODULE(keepalive);

static bool keepalive_enable = false;      /* Keepalive disabled by default. */
static uint32_t keepalive_timer_interval;  /* keepalive timer interval. */
static struct keepalive_info ka_info;

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct smap *keepalive_stats OVS_GUARDED_BY(mutex);

/* Returns true if state update is allowed, false otherwise. */
static bool
ka_can_update_state(void)
{
    bool reload_inprogress;
    bool ka_enable;

    atomic_read_relaxed(&ka_info.reload_threads, &reload_inprogress);
    ka_enable = ka_is_enabled();

    /* Return true if KA is enabled and 'cached_process_list' map reload
     * is completed. */
    return ka_enable && !reload_inprogress;
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
        if (OVS_LIKELY(pinfo->tid == tid)) {
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

/* Returns true if keepalive is enabled, false otherwise. */
bool
ka_is_enabled(void)
{
    return keepalive_enable;
}

/* Return the Keepalive timer interval. */
uint32_t
get_ka_interval(void)
{
    return keepalive_timer_interval;
}

/* 'cached_process_list' map reload in progress.
 *
 * Should be called before the 'ka_info.cached_process_list'
 * is populated from 'ka_info.process_list'. This way the pmd
 * doesn't heartbeat while the reload is in progress. */
void
ka_reload_datapath_threads_begin(void)
{
    atomic_store_relaxed(&ka_info.reload_threads, true);
}

/* 'cached_process_list' map reload finished.
 *
 * Should be called after the 'ka_info.cached_process_list'
 * is populated from 'ka_info.process_list'. This way the pmd
 * can restart heartbeat when the reload is finished. */
void
ka_reload_datapath_threads_end(void)
{
    atomic_store_relaxed(&ka_info.reload_threads, false);
}

/* Register thread to KA framework. */
void
ka_register_thread(pid_t tid)
{
    if (ka_is_enabled()) {
        struct ka_process_info *ka_pinfo;
        int core_id = -1;
        char proc_name[18] = "UNDEFINED";

        struct process_info pinfo;
        int success = get_process_info(tid, &pinfo);
        if (success) {
            core_id = pinfo.core_id;
            ovs_strlcpy(proc_name, pinfo.name, sizeof proc_name);
        }

        uint32_t hash = hash_int(tid, 0);
        ovs_mutex_lock(&ka_info.proclist_mutex);
        HMAP_FOR_EACH_WITH_HASH (ka_pinfo, node,
                                 hash, &ka_info.process_list) {
            /* Thread is already registered. */
            if (ka_pinfo->tid == tid) {
                goto out;
            }
        }

        ka_pinfo = xmalloc(sizeof *ka_pinfo);
        ka_pinfo->tid = tid;
        ka_pinfo->core_id = core_id;
        ovs_strlcpy(ka_pinfo->name, proc_name, sizeof ka_pinfo->name);

        hmap_insert(&ka_info.process_list, &ka_pinfo->node, hash);

        ka_pinfo->state = KA_STATE_ALIVE;
        ka_pinfo->last_seen_time = time_wall_msec();
        ka_info.thread_cnt++;  /* Increment count of registered threads. */
out:
        ovs_mutex_unlock(&ka_info.proclist_mutex);
    }
}

/* Unregister thread from KA framework. */
void
ka_unregister_thread(pid_t tid)
{
    if (ka_is_enabled()) {
        struct ka_process_info *ka_pinfo;

        ovs_mutex_lock(&ka_info.proclist_mutex);
        HMAP_FOR_EACH_WITH_HASH (ka_pinfo, node, hash_int(tid, 0),
                                 &ka_info.process_list) {
            /* If thread is registered, remove it from the list */
            if (ka_pinfo->tid == tid) {
                hmap_remove(&ka_info.process_list, &ka_pinfo->node);
                free(ka_pinfo);

                ka_pinfo->state = KA_STATE_UNUSED;
                ka_info.thread_cnt--;  /* Decrement thread count. */
                break;
            }
        }
        ovs_mutex_unlock(&ka_info.proclist_mutex);
    }
}

/* Free the 'ka_info.cached_process_list' list. */
void
ka_free_cached_threads(void)
{
    struct ka_process_info *pinfo_cached;
    /* Free threads in the cached list. */
    HMAP_FOR_EACH_POP (pinfo_cached, node, &ka_info.cached_process_list) {
        free(pinfo_cached);
    }
    hmap_shrink(&ka_info.cached_process_list);
}

/* Cache the list of registered threads from 'ka_info.process_list'
 * map into 'ka_info.cached_process_list.
 *
 * 'cached_process_list' map is an exact copy of 'process_list' that will
 * be updated by 'pmd' and 'ovs_keepalive' threads as part of heartbeat
 * mechanism.  This cached copy is created so that the heartbeats can be
 * performed with out acquiring locks.
 *
 * On datapath reconfiguration, both the 'process_list' and the cached copy
 * 'cached_process_list' is updated after setting 'reload_threads' to 'true'
 * so that pmd doesn't heartbeat while the maps are updated.
 *
 */
void
ka_cache_registered_threads(void)
{
    struct ka_process_info *pinfo, *next, *pinfo_cached;

    ka_free_cached_threads();

    HMAP_FOR_EACH_SAFE (pinfo, next, node, &ka_info.process_list) {
        pinfo_cached = xmemdup(pinfo, sizeof *pinfo_cached);
        hmap_insert(&ka_info.cached_process_list, &pinfo_cached->node,
                     hash_int(pinfo->tid,0));
    }
}

/* Mark packet processing thread alive. */
void
ka_mark_pmd_thread_alive(int tid)
{
    if (ka_can_update_state()) {
        struct ka_process_info *pinfo;
        HMAP_FOR_EACH_WITH_HASH (pinfo, node, hash_int(tid, 0),
                             &ka_info.cached_process_list) {
            if (OVS_LIKELY(pinfo->tid == tid)) {
                pinfo->state = KA_STATE_ALIVE;
            }
        }
    }
}

/* Mark packet processing thread as sleeping. */
void
ka_mark_pmd_thread_sleep(int tid)
{
    if (ka_can_update_state()) {
        struct ka_process_info *pinfo;

        HMAP_FOR_EACH_WITH_HASH (pinfo, node, hash_int(tid, 0),
                             &ka_info.cached_process_list) {
            if (pinfo->tid == tid) {
                pinfo->state = KA_STATE_SLEEP;
            }
        }
    }
}

static void
get_pmd_status(struct smap *ka_pmd_stats)
    OVS_REQUIRES(ka_info.proclist_mutex)
{
    struct ka_process_info *pinfo, *pinfo_next;
    HMAP_FOR_EACH_SAFE (pinfo, pinfo_next, node, &ka_info.process_list) {
        char *state = NULL;
        if (pinfo->state == KA_STATE_UNUSED) {
            continue;
        }

        switch (pinfo->state) {
        case KA_STATE_ALIVE:
            state = "ALIVE";
            break;
        case KA_STATE_MISSING:
            state = "MISSING";
            break;
        case KA_STATE_DEAD:
            state = "DEAD";
            break;
        case KA_STATE_GONE:
            state = "GONE";
            break;
        case KA_STATE_SLEEP:
            state = "SLEEP";
            break;
        case KA_STATE_UNUSED:
            break;
        default:
            OVS_NOT_REACHED();
        }

        smap_add_format(ka_pmd_stats, pinfo->name, "%s,%d,%ld",
                        state, pinfo->core_id, pinfo->last_seen_time);
    }
}

void
get_ka_stats(void)
{
    struct smap *ka_pmd_stats;
    ka_pmd_stats = xmalloc(sizeof *ka_pmd_stats);
    smap_init(ka_pmd_stats);

    ovs_mutex_lock(&ka_info.proclist_mutex);
    get_pmd_status(ka_pmd_stats);
    ovs_mutex_unlock(&ka_info.proclist_mutex);

    ovs_mutex_lock(&mutex);
    if (keepalive_stats) {
        smap_destroy(keepalive_stats);
        free(keepalive_stats);
        keepalive_stats = NULL;
    }
    keepalive_stats = ka_pmd_stats;
    ovs_mutex_unlock(&mutex);
}

struct smap *
ka_stats_run(void)
{
    struct smap *ka_stats = NULL;

    ovs_mutex_lock(&mutex);
    if (keepalive_stats) {
        ka_stats = keepalive_stats;
        keepalive_stats = NULL;
    }
    ovs_mutex_unlock(&mutex);

    return ka_stats;
}

static void
ka_unixctl_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "keepAlive Status: %s",
                  ka_is_enabled() ? "Enabled" : "Disabled");

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
ka_unixctl_pmd_health_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                           const char *argv[] OVS_UNUSED, void *ka_info_)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds,
                  "\n\t\tKeepalive status\n\n");

    ds_put_format(&ds, "keepalive status   : %s\n",
                  ka_is_enabled() ? "Enabled" : "Disabled");

    if (!ka_is_enabled()) {
        goto out;
    }

    ds_put_format(&ds, "keepalive interval : %"PRIu32" ms\n",
                  get_ka_interval());

    char *utc = xastrftime_msec("%d %b %Y %H:%M:%S",
                                    ka_info.init_time, true);
    ds_put_format(&ds, "keepalive init time: %s \n", utc);

    struct keepalive_info *ka_info = (struct keepalive_info *)ka_info_;
    if (OVS_UNLIKELY(!ka_info)) {
        goto out;
    }

    ds_put_format(&ds, "PMD threads        : %"PRIu32" \n", ka_info->thread_cnt);
    ds_put_format(&ds,
                  "\n PMD\tCORE\tSTATE\tLAST SEEN TIMESTAMP(UTC)\n");

    struct ka_process_info *pinfo, *pinfo_next;

    ovs_mutex_lock(&ka_info->proclist_mutex);
    HMAP_FOR_EACH_SAFE (pinfo, pinfo_next, node, &ka_info->process_list) {
        char *state = NULL;

        if (pinfo->state == KA_STATE_UNUSED) {
            continue;
        }

        switch (pinfo->state) {
        case KA_STATE_ALIVE:
            state = "ALIVE";
            break;
        case KA_STATE_MISSING:
            state = "MISSING";
            break;
        case KA_STATE_DEAD:
            state = "DEAD";
            break;
        case KA_STATE_GONE:
            state = "GONE";
            break;
        case KA_STATE_SLEEP:
            state = "SLEEP";
            break;
        case KA_STATE_UNUSED:
            break;
        default:
            OVS_NOT_REACHED();
        }

        utc = xastrftime_msec("%d %b %Y %H:%M:%S",
                                    pinfo->last_seen_time, true);

        ds_put_format(&ds, "%s\t%2d\t%s\t%s\n",
                      pinfo->name, pinfo->core_id, state, utc);

        free(utc);
    }
    ovs_mutex_unlock(&ka_info->proclist_mutex);

    ds_put_format(&ds, "\n");
out:
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/* Dispatch heartbeats from 'ovs_keepalive' thread. */
void
dispatch_heartbeats(void)
{
    struct ka_process_info *pinfo, *pinfo_next;

    /* Iterates over the list of processes in 'cached_process_list' map. */
    HMAP_FOR_EACH_SAFE (pinfo, pinfo_next, node,
                        &ka_info.cached_process_list) {
        if (pinfo->state == KA_STATE_UNUSED) {
            continue;
        }

        switch (pinfo->state) {
        case KA_STATE_UNUSED:
            break;
        case KA_STATE_ALIVE:
            pinfo->state = KA_STATE_MISSING;
            pinfo->last_seen_time = time_wall_msec();
            break;
        case KA_STATE_MISSING:
            pinfo->state = KA_STATE_DEAD;
            break;
        case KA_STATE_DEAD:
            pinfo->state = KA_STATE_GONE;
            break;
        case KA_STATE_GONE:
            break;
        case KA_STATE_SLEEP:
            pinfo->state = KA_STATE_SLEEP;
            pinfo->last_seen_time = time_wall_msec();
            break;
        default:
            OVS_NOT_REACHED();
        }

        /* Invoke 'ka_update_thread_state' cb function to update state info
         * in to 'ka_info.process_list' map. */
        ka_info.relay_cb(pinfo->tid, pinfo->state, pinfo->last_seen_time);
    }
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
            hmap_init(&ka_info.cached_process_list);

            ka_info.init_time = time_wall_msec();

            unixctl_command_register("keepalive/status", "", 0, 0,
                                      ka_unixctl_status, NULL);

            unixctl_command_register("keepalive/pmd-health-show", "", 0, 0,
                                      ka_unixctl_pmd_health_show, &ka_info);

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

    ka_free_cached_threads();
    hmap_destroy(&ka_info.cached_process_list);
    ovs_mutex_destroy(&ka_info.proclist_mutex);
}
