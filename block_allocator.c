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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "block_allocator.h"
#include "debug.h"
#include "transaction.h"

bool print_block_alloc = false;

/**
 * find_free_block - Search for a free block
 * @tr:             Transaction object.
 * @min_block_in:   Block number to start search at.
 *
 * Return: Block number that is in commited free set and not already allocated
 * by any transaction.
 */
static data_block_t find_free_block(struct transaction *tr,
                                    data_block_t min_block_in)
{
    data_block_t block;
    data_block_t min_block = min_block_in;
    struct block_set *set;

    assert(list_in_list(&tr->node)); /* transaction must be active */

    pr_read("min_block %lld\n", min_block);

    block = min_block;
    do {
        block = block_set_find_next_block(tr, &tr->fs->free, block, true);
        if (tr->failed) {
            return 0;
        }
        if (block < min_block) {
            assert(!block);

            if (LOCAL_TRACE >= TRACE_LEVEL_READ) {
                if (min_block_in) {
                    block = find_free_block(tr, 0);
                }
                printf("%s: no space, min_block %lld, free block ignoring_min_block %lld\n",
                       __func__, min_block_in, block);

                printf("%s: free\n", __func__);
                block_set_print(tr, &tr->fs->free);
                list_for_every_entry(&tr->fs->allocated, set, struct block_set, node) {
                    printf("%s: allocated %p\n", __func__, set);
                    block_set_print(tr, set);
                }
                if (tr->new_free_set) {
                    printf("%s: new free\n", __func__);
                    block_set_print(tr, tr->new_free_set);
                }
            }

            return 0;
        }

        min_block = block;

        pr_read("check free block %lld\n", block);

        assert(!list_is_empty(&tr->fs->allocated));
        list_for_every_entry(&tr->fs->allocated, set, struct block_set, node) {
            block = block_set_find_next_block(tr, set, block, false);
            if (tr->failed) {
                return 0;
            }
            assert(block >= min_block);
        };
    } while (block != min_block);

    pr_read("found free block %lld\n", block);

    return block;
}

/**
 * block_allocate_etc - Allocate a block
 * @tr:         Transaction object.
 * @is_tmp:     %true if allocated block should be automatically freed when
 *              transaction completes, %false if allocated block should be added
 *              to free set when transaction completes.
 *
 * Find a free block and add it to the allocated set selected by @is_tmp. If
 * called while completing the transaction update the new free set directly if
 * needed.
 *
 * Return: Allocated block number.
 */
data_block_t block_allocate_etc(struct transaction *tr, bool is_tmp)
{
    data_block_t block;
    data_block_t min_block;

    if (tr->failed) {
        pr_warn("transaction failed, abort\n");

        return 0;
    }
    assert(transaction_is_active(tr));

    /* TODO: group allocations by set */
    if (is_tmp) {
        if (!tr->tmp_allocated.updating) {
            tr->last_tmp_free_block = tr->fs->dev->block_count / 4 * 3;
        }
    } else {
        if (!tr->new_free_set || !tr->new_free_set->updating) {
            tr->last_free_block = 0;
        }
    }
    min_block = is_tmp ? tr->last_tmp_free_block : tr->last_free_block;

    block = find_free_block(tr, min_block);
    if (!block) {
        block = find_free_block(tr, 0);
        if (!block) {
            if (!tr->failed) {
                pr_err("no space\n");
                transaction_fail(tr);
            }
            return 0;
        }
    }

    if (is_tmp) {
        pr_write("add %lld to tmp_allocated\n", block);

        block_set_add_block(tr, &tr->tmp_allocated, block);
        tr->last_tmp_free_block = block + 1;
    } else {
        pr_write("add %lld to allocated\n", block);

        block_set_add_block(tr, &tr->allocated, block);

        if (block < tr->min_free_block) {
            pr_write("remove %lld from new_free_set\n", block);

            assert(tr->new_free_set);
            block_set_remove_block(tr, tr->new_free_set, block);
            tr->last_free_block = block + 1;
        }
    }

    if (tr->failed) {
        return 0;
    }

    return block;
}

/**
 * block_free_etc - Free a block
 * @tr:         Transaction object.
 * @block:      Block that should be freed.
 * @is_tmp:     Must match is_tmp value passed to block_allocate_etc (always
 *              %false if @block was not allocated by this transaction).
 *
 * If @block was allocated in this transaction, remove it from the allocated set
 * (selected by @is_tmp). Otherwise add it to the set of blocks to remove when
 * transaction completes. If called while completing the transaction update the
 * new free set directly if needed.
 */
void block_free_etc(struct transaction *tr, data_block_t block, bool is_tmp)
{
    assert(block_is_clean(tr->fs->dev, block));
    if (is_tmp) {
        assert(!block_set_block_in_set(tr, &tr->allocated, block));
        assert(!block_set_block_in_set(tr, &tr->freed, block));

        pr_write("remove %lld from tmp_allocated\n", block);

        block_set_remove_block(tr, &tr->tmp_allocated, block);

        return;
    }

    assert(!block_set_block_in_set(tr, &tr->tmp_allocated, block));
    if (block_set_block_in_set(tr, &tr->allocated, block)) {
        pr_write("remove %lld from allocated\n", block);

        block_set_remove_block(tr, &tr->allocated, block);

        if (block < tr->min_free_block) {
            pr_write("add %lld to new_free_root\n", block);

            assert(tr->new_free_set);
            block_set_add_block(tr, tr->new_free_set, block);
        }
    } else {
        if (block < tr->min_free_block) {
            pr_write("add %lld to new_free_root\n", block);

            assert(tr->new_free_set);
            block_set_add_block(tr, tr->new_free_set, block);
        } else {
            pr_write("add %lld to freed\n", block);

            block_set_add_block(tr, &tr->freed, block);
        }
    }
}
