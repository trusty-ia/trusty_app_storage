/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <trusty_std.h>

#pragma pack (1)
typedef struct rpmb_block {
	uint8_t  signature[4];
	uint32_t length;
	uint32_t revision;
	uint32_t flag;
	uint16_t attkb_addr;
	uint32_t attkb_size;
	uint16_t attkb_svn;
	uint16_t uos_rpmb_size;
	uint8_t  reserved[230];
} rpmb_block_t;
#pragma pack ()

extern struct rpmb_state *g_rpmb_state;
