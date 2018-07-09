/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __RPMB_H__
#define __RPMB_H__

struct rpmb_key {
    uint8_t     byte[32];
};

struct rpmb_state {
    struct rpmb_key     key;
    void                *mmc_handle;
    uint32_t            write_counter;
};

#define RPMB_BUF_SIZE 256

enum rpmb_result {
    RPMB_RES_OK                         = 0x0000,
    RPMB_RES_GENERAL_FAILURE            = 0x0001,
    RPMB_RES_AUTH_FAILURE               = 0x0002,
    RPMB_RES_COUNT_FAILURE              = 0x0003,
    RPMB_RES_ADDR_FAILURE               = 0x0004,
    RPMB_RES_WRITE_FAILURE              = 0x0005,
    RPMB_RES_READ_FAILURE               = 0x0006,
    RPMB_RES_NO_AUTH_KEY                = 0x0007,

    RPMB_RES_WRITE_COUNTER_EXPIRED      = 0x0080,
};

/* provides */
int rpmb_init(struct rpmb_state **statep,
              void *mmc_handle,
              const struct rpmb_key *key);
void rpmb_uninit(struct rpmb_state *statep);
int rpmb_read(struct rpmb_state *state, void *buf, uint16_t addr, uint16_t count);
/* count must be 1 or 2, addr must be aligned */
int rpmb_write(struct rpmb_state *state, const void *buf, uint16_t addr, uint16_t count, bool sync);
int rpmb_program_key(struct rpmb_state *state);
int rpmb_read_counter(struct rpmb_state *state, uint32_t *write_counter, uint16_t *result);

/* needs */
int rpmb_send(void *mmc_handle,
              void *reliable_write_buf, size_t reliable_write_size,
              void *write_buf, size_t write_buf_size,
              void *read_buf, size_t read_buf_size, bool sync);

#endif
