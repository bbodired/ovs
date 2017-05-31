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

#ifndef KEEPALIVE_H
#define KEEPALIVE_H

#include <stdint.h>
#include "openvswitch/hmap.h"
#include "ovs-thread.h"

/* Default timeout set to 1000ms */
#define OVS_KEEPALIVE_DEFAULT_TIMEOUT 1000

struct smap;

/*
 * Keepalive states with description
 *
 * KA_STATE_UNUSED  - Not registered to KA framework.
 * KA_STATE_ALIVE   - Thread is alive.
 * KA_STATE_MISSING - Thread missed first heartbeat.
 * KA_STATE_DEAD    - Thread missed two heartbeats.
 * KA_STATE_GONE    - Thread missed two or more heartbeats
 *                    and is completely 'burried'.
 * KA_STATE_SLEEP   - Thread is sleeping.
 *
 */
enum keepalive_state {
    KA_STATE_UNUSED,
    KA_STATE_ALIVE,
    KA_STATE_DEAD,
    KA_STATE_GONE,
    KA_STATE_MISSING,
    KA_STATE_SLEEP,
};

struct ka_process_info {
    /* Thread id of the process, retrieved using ovs_gettid(). */
    pid_t tid;

    /* Core id the thread was last scheduled. */
    int core_id;

    /* Last seen thread state. */
    enum keepalive_state state;

    /* Last seen timestamp of the thread. */
    uint64_t last_seen_time;
    struct hmap_node node;
};

typedef void (*ka_relay_cb)(int, enum keepalive_state, uint64_t);

struct keepalive_info {
    /* Mutex for 'process_list'. */
    struct ovs_mutex proclist_mutex;

    /* List of process/threads monitored by KA framework. */
    struct hmap process_list OVS_GUARDED;

    /* Keepalive initialization time. */
    uint64_t init_time;

    /* keepalive relay handler. */
    ka_relay_cb relay_cb;
    void *relay_cb_data;
};

bool ka_is_enabled(void);
void ka_init(const struct smap *);
void ka_destroy(void);

#endif /* keepalive.h */
