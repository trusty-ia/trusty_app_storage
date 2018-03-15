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

#include <assert.h>
#include <uapi/err.h>
#include <lk/list.h> // for containerof
#include <stdlib.h>
#include <string.h>

#include <interface/storage/storage.h>
#include <lib/hwkey/hwkey.h>
#include <openssl/mem.h>

#include "trusty_key_migration.h"
#include "ipc.h"
#include "rpmb.h"
#include "session.h"

#include "trusty_device_info.h"
#include "trusty_syscalls_x86.h"

#define SS_ERR(args...)  fprintf(stderr, "ss: " args)
#define CRYPTO_CONTEXT_RPMB_ADDR	(1024)

static bool init_connection = true;
static uint8_t g_rpmb_key[32] = {0};
static bool g_setup_flag = false;

static void proxy_disconnect(struct ipc_channel_context *ctx);

static struct storage_session *proxy_context_to_session(struct ipc_channel_context *context)
{
	assert(context != NULL);
	struct storage_session *session =
	        containerof(context, struct storage_session, proxy_ctx);
	assert(session->magic == STORAGE_SESSION_MAGIC);
	return session;
}

static int get_storage_encryption_key(hwkey_session_t session, uint8_t *key,
                                      uint32_t key_size)
{
	uint32_t size = key_size;

	int rc = hwkey_get_ssek(session, key, size);
	if (rc) {
		SS_ERR("%s: failed to get encryption key: %d, size: %u.\n", __func__, rc, size);
		return rc;
	}

	return NO_ERROR;
}

static int get_rpmb_auth_key(hwkey_session_t session, uint8_t *key,
                             uint32_t key_size)
{
	const char *storage_auth_key_id =
	        "com.android.trusty.storage_auth.rpmb";

	int rc = hwkey_get_keyslot_data(session, storage_auth_key_id, key,
	                                &key_size);
	if (rc < 0) {
		SS_ERR("%s: failed to get key: %d\n", __func__, rc);
		return rc;
	}

	return NO_ERROR;
}

/* if rpmb is not programmed, use seed[0] derived rpmb auth key to program.
 * else, test up to num_seeds keys to get the correct one.
 */
static int get_programmed_rpmb_auth_key(handle_t chan_handle, hwkey_session_t hwkey_session)
{
	struct rpmb_key rpmb_keys[CSE_SEED_MAX_ENTRIES];
	trusty_device_info_t dev_info;
	struct rpmb_state state;
	uint32_t i;
	int rc = -1;
	uint32_t write_counter = 0;
	uint16_t result = -1;

	if (NO_ERROR != get_device_info(&dev_info)) {
		SS_ERR("%s:failed to get device infomation\n", __func__);
		goto out;
	}

	/* Init RPMB key */
	switch (dev_info.sec_info.platform)
	{
		case APL_PLATFORM:
			rc = get_rpmb_auth_key(hwkey_session, (uint8_t *)&rpmb_keys, sizeof(rpmb_keys));
			if (rc < 0) {
				SS_ERR("%s: can't get storage auth key: (%d)\n", __func__, rc);
				goto out;
			}

			state.mmc_handle = &chan_handle;
			for (i = 0; i < dev_info.sec_info.num_seeds; i++) {
				memcpy_s(&state.key, 32, rpmb_keys[i].byte, 32);
				rc = rpmb_read_counter(&state, &write_counter, &result);
				if (rc == 0)
					break;
				if (result == RPMB_RES_NO_AUTH_KEY) {
					SS_ERR("%s: key is not programmed.\n", __func__);
					goto out;
				}
				if (result != RPMB_RES_AUTH_FAILURE) {
					SS_ERR("%s: rpmb_read_counter unexpected error: %d.\n", __func__, result);
					goto out;
				}
			}

			if (i >= dev_info.sec_info.num_seeds) {
				SS_ERR("%s: Fatal error: All keys are not match!\n", __func__);
				goto out;
			}

			if (i != 0)
				SS_ERR("%s: seed changed to %d.\n", __func__, i);
			memcpy_s(g_rpmb_key, 32, rpmb_keys[i].byte, 32);
			rc = 0;

			break;

		case ICL_PLATFORM:
			rc = get_rpmb_auth_key(hwkey_session, (uint8_t *)&rpmb_keys, sizeof(rpmb_keys));
			if (rc < 0) {
				SS_ERR("%s: icl can't get storage auth key: (%d)\n", __func__, rc);
				goto out;
			}

			state.mmc_handle = &chan_handle;
			memcpy_s(&state.key, 32, rpmb_keys[0].byte, 32);

			for (i = 0; i < 32; i++) {
				SS_ERR("%s: icl rpmb_key:(%d)(0x%x)\n", __func__, i, rpmb_keys[0].byte[i]);
			}

			rc = rpmb_read_counter(&state, &write_counter, &result);
			if (rc != 0) {
				SS_ERR("%s: icl rpmb_read_counter unexpected error: %d.\n", __func__, result);
				goto out;
			}

			memcpy_s(g_rpmb_key, 32, rpmb_keys[0].byte, 32);
			rc = 0;

			break;

		default:
			//TODO: CWP rpmb key.
			SS_ERR("%s: platform(%d) is not handled!\n", __func__, dev_info.sec_info.platform);
			assert(0);
			break;
	}

out:
	secure_memzero(rpmb_keys, sizeof(rpmb_keys));
	secure_memzero(&state, sizeof(struct rpmb_state));
	secure_memzero(&dev_info, sizeof(trusty_device_info_t));

	return rc;
}

struct ipc_channel_context *proxy_connect(struct ipc_port_context *parent_ctx,
                                          const uuid_t *peer_uuid, handle_t chan_handle)
{
	struct rpmb_key rpmb_key;
	struct rpmb_state state;
	int rc;
	uint8_t buf[256] = {0};
	struct crypto_context crypto_ctx = {0};
	struct crypto_context updated_crypto_ctx = {0};

	struct storage_session *session = calloc(1, sizeof(*session));
	if (session == NULL) {
		SS_ERR("%s: out of memory\n", __func__);
		goto err_alloc_session;
	}

	memset(&state, 0, sizeof(struct rpmb_state));
	session->magic = STORAGE_SESSION_MAGIC;

	rc = hwkey_open();
	if (rc < 0) {
		SS_ERR("%s: hwkey init failed: %d\n", __func__, rc);
		goto err_hwkey_open;
	}

	hwkey_session_t hwkey_session = (hwkey_session_t) rc;

	state.mmc_handle = &chan_handle;

	SS_ERR("init_connection is %d.\n", init_connection);

	if (init_connection) {
		init_connection = false;

		if (get_programmed_rpmb_auth_key(chan_handle, hwkey_session)) {
			SS_ERR("%s: get_programmed_rpmb_auth_key failed.\n", __func__);
			goto err_init_connection;
		}

		memcpy_s(state.key.byte, 32, g_rpmb_key, 32);
		if (rpmb_read(&state, buf, CRYPTO_CONTEXT_RPMB_ADDR, 1)) {
			SS_ERR("%s: rpmb_read CRYPTO_CONTEXT_RPMB_ADDR failed.\n", __func__);
			goto err_init_connection;
		}
		if (memcpy_s(&crypto_ctx, sizeof(crypto_ctx), buf, sizeof(buf))) {
			SS_ERR("%s: failed to copy buf to crypto_ctx.\n", __func__);
			goto err_init_connection;
		}

		if (crypto_ctx.magic != CRYPTO_CONTEXT_MAGIC_DATA) {
			SS_ERR("%s: CRYPTO CONTEXT ARE NOT EXISTED.\n", __func__);
			if (hwkey_generate_crypto_context(hwkey_session, (uint8_t *)&crypto_ctx, sizeof(crypto_ctx))) {
				SS_ERR("%s: hwkey_generate_crypto_context failed.\n", __func__);
				goto err_init_connection;
			}

			if (memcpy_s(buf, sizeof(buf), &crypto_ctx, sizeof(crypto_ctx))) {
				SS_ERR("%s: failed to copy crypto_ctx to buf.\n", __func__);
				goto err_init_connection;
			}

			if (rpmb_write(&state, buf, CRYPTO_CONTEXT_RPMB_ADDR, 1, true)) {
				SS_ERR("%s: rpmb_write CRYPTO_CONTEXT_RPMB_ADDR failed.\n", __func__);
				goto err_init_connection;
			}
		}
		else {
			SS_ERR("%s: CRYPTO CONTEXT ARE EXISTED.\n", __func__);
			if (hwkey_exchange_crypto_context(hwkey_session, (const uint8_t *)&crypto_ctx,
						 (uint8_t *)&updated_crypto_ctx, sizeof(struct crypto_context))) {
				SS_ERR("%s: hwkey_transfer_enc_seeds failed.\n", __func__);
				goto err_init_connection;
			}
			if (CRYPTO_memcmp(&crypto_ctx, &updated_crypto_ctx, sizeof(struct crypto_context))) {
				SS_ERR("%s: SEED CHANGED!!! Rewrite to rpmb.\n", __func__);
				if (memcpy_s(buf, sizeof(buf), &updated_crypto_ctx, sizeof(struct crypto_context))) {
					SS_ERR("%s: failed to copy updated_crypto_ctx to buf.\n", __func__);
					goto err_init_connection;
				}
				if (rpmb_write(&state, buf, CRYPTO_CONTEXT_RPMB_ADDR, 1, true)) {
					SS_ERR("%s: rpmb_write CRYPTO_CONTEXT_RPMB_ADDR failed.\n", __func__);
					goto err_init_connection;
				}
			}
		}

		g_setup_flag = true;
		goto err_init_connection;
	}

	if (!g_setup_flag) {
		SS_ERR("%s: init connection gets failure. Drop to connect.\n", __func__);
		goto err_init_block_device;
	}

	/* Generate encryption key */
	rc = get_storage_encryption_key(hwkey_session, session->key.byte, sizeof(session->key.byte));
	if (rc < 0) {
		SS_ERR("%s: can't get storage key: (%d) \n", __func__, rc);
		goto err_get_storage_key;
	}

	memcpy_s(&rpmb_key, 32, g_rpmb_key, 32);
	/* keep in memory, because it may be called more than 2 times
         * secure_memzero(g_rpmb_key, 32); */

	rc = block_device_tipc_init(&session->block_device, chan_handle,
	                            &session->key, &rpmb_key);
	if (rc < 0) {
		SS_ERR("%s: block_device_tipc_init failed (%d)\n", __func__, rc);
		goto err_init_block_device;
	}

	session->proxy_ctx.ops.on_disconnect = proxy_disconnect;

	hwkey_close(hwkey_session);

	return &session->proxy_ctx;

err_init_connection:
	secure_memzero(&updated_crypto_ctx, sizeof(struct crypto_context));
	secure_memzero(&crypto_ctx, sizeof(struct crypto_context));
	secure_memzero(buf, sizeof(buf));
	secure_memzero(&state, sizeof(state));
err_init_block_device:
err_get_rpmb_key:
err_program_key:
	secure_memzero(session->key.byte, sizeof(session->key.byte));
err_get_storage_key:
	hwkey_close(hwkey_session);
err_hwkey_open:
	free(session);
err_alloc_session:
	return NULL;
}

void proxy_disconnect(struct ipc_channel_context *ctx)
{
	struct storage_session *session = proxy_context_to_session(ctx);

	block_device_tipc_uninit(&session->block_device);

	free(session);
}
