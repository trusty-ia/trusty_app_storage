/*
 * Copyright (C) 2015-2016 The Android Open Source Project
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
#include <compiler.h>
#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "array.h"
#include "block_allocator.h"
#include "block_set.h"
#include "debug.h"
#include "transaction.h"

/**
 * block_range_init_from_path
 * @range:      range object to initialize.
 * @path:       Block tree path.
 *
 * Helper function to initialize a block_range from a tree entry.
 */
static void block_range_init_from_path(struct block_range *range,
                                       struct block_tree_path *path)
{
    if (!path->count) {
        block_range_clear(range);
        return;
    }
    range->start = block_tree_path_get_key(path);
    range->end = block_tree_path_get_data(path);
    assert(!range->end == !range->start);
}

/**
 * block_range_extend - Extend range if possible
 * @range:      range object to initialize.
 * @add_range:  Range to add
 *
 * Return: %true if @add_range was adjacent to @range, %false otherwise.
 */
static bool block_range_extend(struct block_range *range,
                               struct block_range add_range)
{
    pr_write("%lld-%lld, %lld-%lld\n",
             range->start, range->end - 1, add_range.start, add_range.end - 1);
    assert(!block_range_empty(add_range));
    assert(!block_range_overlap(*range, add_range));
    if (block_range_empty(*range)) {
        pr_write("failed, *range is empty\n");
        return false;
    }
    if (add_range.end == range->start) {
        range->start = add_range.start;
    } else if (add_range.start == range->end) {
        range->end = add_range.end;
    } else {
        pr_write("failed\n");
        return false;
    }

    pr_write("now %lld-%lld\n", range->start, range->end - 1);

    return true;
}

/**
 * block_range_shrink - Shrink range if possible
 * @range:          range object to initialize.
 * @remove_range:   Range to remove
 *
 * Return: %true if @remove_range was at either end of @range, %false otherwise.
 */
static bool block_range_shrink(struct block_range *range,
                               struct block_range remove_range)
{
    pr_write("%lld-%lld, %lld-%lld\n", range->start, range->end - 1,
             remove_range.start, remove_range.end - 1);
    assert(block_range_is_sub_range(*range, remove_range));
    if (remove_range.start == range->start) {
        assert(!block_range_empty(*range));
        range->start = remove_range.end;
    } else if (remove_range.end == range->end) {
        assert(!block_range_empty(*range));
        range->end = remove_range.start;
    } else {
        pr_write("%s: failed\n", __func__);
        return false;
    }

    pr_write("now %lld-%lld\n", range->start, range->end - 1);

    return true;
}

/**
 * block_set_print_ranges - Print block-set ranges
 * @tr:         Transaction object.
 * @set:        Block-set object.
 */
static void block_set_print_ranges(struct transaction *tr,
                                   struct block_set *set)
{
    struct block_tree_path path;
    struct block_range range;
    int split_line = 0;
    uint i;

    printf("set:\n");

    block_tree_walk(tr, &set->block_tree, 0, true, &path);
    block_range_init_from_path(&range, &path);
    while (!block_range_empty(range)) {
        if (split_line >= 8) {
            split_line = 0;
            printf("\n");
        }
        split_line++;
        if (range.start == range.end - 1) {
            printf("    %3lld      ",range.start);
        } else {
            printf("    %3lld - %3lld",range.start, range.end - 1);
        }
        split_line++;
        block_tree_path_next(&path);
        block_range_init_from_path(&range, &path);
    }
    printf("\n");

    if (!block_range_empty(set->inserting_range[0])) {
        printf("inserting_range: ");
        split_line = 0;
        for (i = 0; i < countof(set->inserting_range); i++) {
            range = set->inserting_range[i];
            if (!block_range_empty(range)) {
                if (split_line >= 8) {
                    split_line = 0;
                    printf("\n");
                }
                split_line++;
                if (range.start == range.end - 1) {
                    printf("    %3lld      ",range.start);
                } else {
                    printf("    %3lld - %3lld",range.start, range.end - 1);
                }
                split_line++;
            }
        }
        printf("\n");
    }

    if (!block_range_empty(set->removing_range[0])) {
        printf("removing_range: ");
        split_line = 0;
        for (i = 0; i < countof(set->removing_range); i++) {
            range = set->removing_range[i];
            if (!block_range_empty(range)) {
                if (split_line >= 8) {
                    split_line = 0;
                    printf("\n");
                }
                split_line++;
                if (range.start == range.end - 1) {
                    printf("    %3lld      ",range.start);
                } else {
                    printf("    %3lld - %3lld",range.start, range.end - 1);
                }
                split_line++;
            }
        }
        printf("\n");
    }
}

/**
 * block_set_print - Print block-set ranges and the tree that stored them
 * @tr:         Transaction object.
 * @set:        Block-set object.
 */
void block_set_print(struct transaction *tr, struct block_set *set)
{
    printf("block_tree:\n");
    block_tree_print(tr, &set->block_tree);
    block_set_print_ranges(tr, set);
}

/**
 * block_set_check_ranges - Check that ranges in block-set are valid
 * @tr:         Transaction object.
 * @set:        Block-set object.
 *
 * Check that ranges in @set are valid, sorted, non-overlapping, non-adjacent
 * and only contain blocks that are valid for @tr.
 *
 * Return: %true if the ranges in @set are valid, %false otherwise.
 */
static bool block_set_check_ranges(struct transaction *tr,
                                   struct block_set *set)
{
    struct block_tree_path path;
    data_block_t min = tr->fs->min_block_num;
    data_block_t max = tr->fs->dev->block_count;
    struct block_range range;

    block_tree_walk(tr, &set->block_tree, 0, true, &path);
    block_range_init_from_path(&range, &path);
    while (!block_range_empty(range)) {
        if (range.start < min) {
            pr_err("bad range start %lld < %lld\n", range.start, min);
            return false;
        }
        if (range.end <= range.start) {
            pr_err("bad range end %lld <= start %lld\n",
                   range.end, range.start);
            return false;
        }
        if (range.end > max) {
            pr_err("bad range end %lld > max %lld\n", range.end, max);
            return false;
        }
        min = range.end + 1;
        block_tree_path_next(&path);
        block_range_init_from_path(&range, &path);
    }

    return true;
}

/**
 * block_set_check - Check block-set tree and ranges
 * @tr:         Transaction object.
 * @set:        Block-set object.
 *
 * Return: %true if the tree and ranges in @set are valid, %false otherwise.
 */
bool block_set_check(struct transaction *tr, struct block_set *set)
{
    bool valid;

    valid = block_tree_check(tr, &set->block_tree);
    if (!valid) {
        return false;
    }
    valid = block_set_check_ranges(tr, set);
    if (!valid) {
        printf("%s: invalid block_set:\n", __func__);
        block_set_print(tr, set);
    }
    return valid;
}

/**
 * block_set_lookup_inserted_range
 * @set:        Block-set object.
 * @min_block:  Block number.
 * @range:      Range to store result in.
 *
 * Find a inserting range in containing @min_block or, if this range does not
 * exist, the first range to start above @min_block.
 */
static void block_set_lookup_inserted_range(struct block_set *set,
                                            data_block_t min_block,
                                            struct block_range *range)
{
    uint i;
    int best_i = -1;

    for (i = 0; i < countof(set->inserting_range); i++) {
        if (block_range_empty(set->inserting_range[i])) {
            break;
        }
        if (block_in_range(set->inserting_range[i], min_block)) {
            best_i = i;
            break;
        }
        if (set->inserting_range[i].start > min_block
            && (best_i < 0 ||
                set->inserting_range[i].start < set->inserting_range[best_i].start)) {
            best_i = i;
        }
    }
    if (best_i >= 0) {
        *range = set->inserting_range[best_i];
    } else {
        block_range_clear(range);
    }
    if (!block_range_empty(*range)) {
        pr_read("%lld return [%lld-%lld]\n",
                min_block, range->start, range->end - 1);
    }
}

/**
 * block_set_remove_inserted_range - remove range from inserting_range
 * @set:        Block-set object.
 * @range:      Range to remove.
 *
 * Check if @set->inserting_range contains an excact match for @range and
 * if so remove it.
 *
 * Return: %true if @range was in @set->inserting_range, %false otherwise.
 */
static bool block_set_remove_inserted_range(struct block_set *set,
                                            struct block_range range)
{
    uint i;

    for (i = 0; i < countof(set->inserting_range); i++) {
        if (block_range_empty(set->inserting_range[i])) {
            return false;
        }
        if (block_range_eq(set->inserting_range[i], range)) {
            break;
        }
    }
    if (i == countof(set->inserting_range)) {
        return false;
    }
    array_shift_down(set->inserting_range, i, i + 1);
    return true;
}

/**
 * block_set_find_next_block - find a block in or not in set
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @min_block:  Block number to start search at.
 * @in_set:     If %true look for a block in @set. If %false, look for a block
 *              not in @set.
 *
 * Return: First block in or not in @set >= @min_block, or 0 if no match is
 * is found.
 */
data_block_t block_set_find_next_block(struct transaction *tr,
                                       struct block_set *set,
                                       data_block_t min_block,
                                       bool in_set)
{
    struct block_tree_path path;
    struct block_range range;
    struct block_range range_inserting; /* inserted but not yet in on disk tree */
    data_block_t next_start;

retry:
    block_tree_walk(tr, &set->block_tree, min_block, true, &path);
    block_range_init_from_path(&range, &path);
    if (!block_range_empty(range) && range.end <= min_block) {
        block_tree_path_next(&path);
        block_range_init_from_path(&range, &path);
    }
    next_start = range.start;
    block_set_lookup_inserted_range(set, min_block, &range_inserting);

    pr_read("set at %lld, %lld in_set %d, disk [%lld-%lld], mem [%lld-%lld]\n",
            block_mac_to_block(tr, &set->block_tree.root),
            min_block, in_set, range.start, range.end - 1,
            range_inserting.start, range_inserting.end -1);

    /* The block tree walk should not find an empty range that is not 0, 0 */
    assert(!block_range_empty(range) || !range.start);

    if (!block_range_empty(range_inserting)
        && (range_inserting.start < range.start || block_range_empty(range))) {
        if (range_inserting.end < range.start || block_range_empty(range)) {
            next_start = range.start;
            range = range_inserting;
        } else {
            assert(range_inserting.end == range.start);
            range.start = range_inserting.start;
        }
        block_set_lookup_inserted_range(set, range.end, &range_inserting);
        if (!block_range_empty(range_inserting)
            && range_inserting.start < next_start) {
            next_start = range_inserting.start;
        }
    }

    if (block_in_range(range, min_block) == in_set) {
        pr_read("%lld in_set %d, return min_block, %lld\n",
                min_block, in_set, min_block);
        return min_block;
    } else {
        if (!in_set) {
            assert(!block_range_empty(range));
            if (next_start == range.end) {
                min_block = next_start;
                pr_warn("%lld in_set %d, range.end == next_start, %lld, retry\n",
                        min_block, in_set, range.end);
                goto retry;
            }
            assert(next_start != range.end);
            pr_read("%lld in_set %d, return range.end, %lld\n",
                    min_block, in_set, range.end);
            return range.end;
        } else {
            if (!block_range_empty(range)) {
                pr_read("%lld in_set %d, return range.start, %lld\n",
                        min_block, in_set, range.start);
                return range.start;
            } else {
                pr_read("%lld in_set %d, return next_start, %lld\n",
                        min_block, in_set, next_start);
                return next_start;
            }
        }
    }
}

/**
 * block_set_find_next_range - find a range in set
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @min_block:  Block number to start search at.
 *
 * Return: First block range in @set >= @min_block, or and empty range if no
 * match is is found. If the matching range in @set starts before @min_block,
 * the returned range will start at @min_block, not at start of the range in
 * @set.
 */
struct block_range block_set_find_next_range(struct transaction *tr,
                                             struct block_set *set,
                                             data_block_t min_block)
{
    struct block_range range;
    range.start = block_set_find_next_block(tr, set, min_block, true);
    if (range.start) {
        range.end = block_set_find_next_block(tr, set, range.start, false);
    } else {
        range.end = 0;
    }
    return range;
}

/**
 * block_set_block_in_set - Check if block is in set
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @block:      Block number.
 *
 * Return: %true if @block is in @set, %false if @block is not on set/
 */
bool block_set_block_in_set(struct transaction *tr,
                            struct block_set *set,
                            data_block_t block)
{
    return block_set_find_next_block(tr, set, block, true) == block;
}

/**
 * block_set_range_in_set - Check if block range is in set
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @range:      Block range to check.
 *
 * Return: %true if all of @range is in @set, %false if a block in @range is not
 * in @set.
 */
bool block_set_range_in_set(struct transaction *tr,
                            struct block_set *set,
                            struct block_range range)
{
    return block_set_find_next_block(tr, set, range.start, true) == range.start &&
           block_set_find_next_block(tr, set, range.start, false) >= range.end;
}

/**
 * block_set_range_in_set - Check if block range is not set
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @range:      Block range to check.
 *
 * Return: %true if all of @range is not in @set, %false if a block in @range is
 * in @set.
 */
bool block_set_range_not_in_set(struct transaction *tr,
                                struct block_set *set,
                                struct block_range range)
{
    data_block_t block = block_set_find_next_block(tr, set, range.start, true);
    return !block || block >= range.end;
}

/**
 * block_set_overlap - Check if block sets have any overlap
 * @tr:         Transaction object.
 * @set_a:      Block-set object.
 * @set_b:      Block-set object.
 *
 * Return: %true a block is in both @set_s and @set_b, %false if no such block
 * exists.
 */
bool block_set_overlap(struct transaction *tr,
                       struct block_set *set_a,
                       struct block_set *set_b)
{
    struct block_range range_a;
    struct block_range range_b = BLOCK_RANGE_INITIAL_VALUE(range_b);

    while(true) {
        range_a = block_set_find_next_range(tr, set_a, range_b.start);
        if (block_range_empty(range_a)) {
            return false; /* No overlap as there a no more ranges in set_a */
        }
        if (block_in_range(range_b, range_a.start)) {
            return true;
        }

        /* range_a must start after range_b except first iteration */
        assert(range_a.start >= range_b.start);

        range_b = block_set_find_next_range(tr, set_b, range_a.start);
        if (block_range_empty(range_b)) {
            return false; /* No overlap as there a no more ranges in set_b */
        }
        if (block_in_range(range_a, range_b.start)) {
            return true;
        }

        assert(range_b.start > range_a.start);
    }
}

/**
 * block_set_add_inserting_range - Add a range to block set in memory
 * @set:        Block-set object.
 * @range:      Block range to add.
 *
 * Either adds @range to inserting_range or removes @range from removing_range.
 * Removing a subset of a range in removing_range is not supported.
 */
static void block_set_add_inserting_range(struct block_set *set,
                                          struct block_range range)
{
    uint i;
    struct block_range removing_range;

    assert(!block_range_empty(range));

    for (i = 0; i < countof(set->removing_range); i++) {
        removing_range = set->removing_range[i];
        if (block_range_empty(removing_range)) {
            break;
        }
        if (block_range_eq(range, removing_range)) {
            pr_write("range [%lld-%lld], remove remove_range instead\n",
                     range.start, range.end - 1);
            array_shift_down(set->removing_range, i, i + 1);
            return;
        }
        assert(!block_range_overlap(removing_range, range));
    }

    assert(block_range_empty(set->inserting_range[countof(set->inserting_range) - 1]));
    array_insert(set->inserting_range, 0, range); /* TODO: shuffle less data around */
}

/**
 * block_set_add_inserting_range - Remove a range from block set in memory
 * @set:        Block-set object.
 * @range:      Block range to remove.
 *
 * Either adds @range to removing_range or removes @range from inserting_range.
 * Removing a subset of a range in inserting_range is not supported.
 */
static void block_set_add_removing_range(struct block_set *set,
                                         struct block_range range)
{
    bool removed;
    struct block_range inserting_range;

    assert(!block_range_empty(range));

    block_set_lookup_inserted_range(set, range.start, &inserting_range);
    if (block_range_eq(range, inserting_range)) {
        pr_write("range [%lld-%lld], remove inserting_range instead\n",
                 range.start, range.end - 1);
        removed = block_set_remove_inserted_range(set, range);
        assert(removed);
        return;
    }
    assert(!block_range_overlap(inserting_range, range));
    assert(block_range_empty(set->removing_range[countof(set->removing_range) - 1]));
    array_insert(set->removing_range, 0, range); /* TODO: shuffle less data around */
}

/**
 * block_set_tree_insert_range - Add a range to block set tree
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @range:      Block range to add.
 *
 * Add @range to block set b+tree either by extending an existing range in the
 * tree, or by adding a new range to the tree. If an existing tree entry is
 * extended check if the next entry can be merged.
 */
static void block_set_tree_insert_range(struct transaction *tr,
                                        struct block_set *set,
                                        struct block_range range)
{
    struct block_range tree_range;
    struct block_range new_tree_range;
    bool extended;
    struct block_tree_path path;
    bool extend_left = false;
    bool merge;

    assert(set->updating);
    assert(!block_range_empty(range));

    block_tree_walk(tr, &set->block_tree, range.start - 1, true, &path);
    block_range_init_from_path(&tree_range, &path);

    if (!block_range_empty(tree_range) && tree_range.end < range.start) {
        block_tree_path_next(&path);
        block_range_init_from_path(&tree_range, &path);
        if (tree_range.start == range.end) {
            extend_left = true;
        } else {
            /* rewind */
            block_tree_walk(tr, &set->block_tree, range.start - 1, true, &path);
            block_range_init_from_path(&tree_range, &path);
        }
    }
    if (tr->failed) {
        pr_warn("transaction failed, abort\n");
        return;
    }

    assert(!tree_range.end || !block_range_overlap(tree_range, range));
    new_tree_range = tree_range;
    extended = block_range_extend(&new_tree_range, range);
    if (!extended) {
        assert(!extend_left);
        block_tree_insert(tr, &set->block_tree, range.start, range.end); /* TODO: use path for insert point */
    } else {
        block_tree_path_next(&path);
        if (tr->failed) {
            pr_warn("transaction failed, abort\n");
            return;
        }
        merge = block_tree_path_get_key(&path) == new_tree_range.end;
        if (merge) {
            assert(block_tree_path_get_data(&path) > new_tree_range.end);
            new_tree_range.end = block_tree_path_get_data(&path);
        }
        block_tree_update(tr, &set->block_tree,
                          tree_range.start, tree_range.end,
                          new_tree_range.start, new_tree_range.end); /* TODO: use path? */
        if (tr->failed) {
            pr_warn("transaction failed, abort\n");
            return;
        }
        if (merge) {
            /* set has overlapping ranges at this point, TODO: check that set is readable in this state */
            block_tree_remove(tr, &set->block_tree,
                              block_tree_path_get_key(&path),
                              block_tree_path_get_data(&path));
        }
    }
}

/**
 * block_set_tree_remove_range - Remove a range from block set tree
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @range:      Block range to remove.
 *
 * Remove @range from block set b+tree either by shrinking an existing range
 * in the tree, or by splitting an existing range in the tree.
 */
static void block_set_tree_remove_range(struct transaction *tr,
                                        struct block_set *set,
                                        struct block_range range)
{
    struct block_tree_path path;
    struct block_range tree_range;
    struct block_range new_tree_range;
    bool shrunk;

    assert(set->updating);
    assert(!block_range_empty(range));
    full_assert(block_set_check(tr, set));

    block_tree_walk(tr, &set->block_tree, range.start, true, &path);
    block_range_init_from_path(&tree_range, &path);

    if (tr->failed) {
        pr_warn("transaction failed, abort\n");
        return;
    }

    assert(path.count > 0);

    assert(block_range_is_sub_range(tree_range, range));
    new_tree_range = tree_range;
    shrunk = block_range_shrink(&new_tree_range, range);
    if (!shrunk) {
        block_tree_insert(tr, &set->block_tree, range.end, tree_range.end);
        if (tr->failed) {
            pr_warn("transaction failed, abort\n");
            return;
        }
        new_tree_range.end = range.start;
    }
    if (block_range_empty(new_tree_range)) {
        block_tree_remove(tr, &set->block_tree, tree_range.start, tree_range.end);
    } else {
        block_tree_update(tr, &set->block_tree,
                          tree_range.start, tree_range.end,
                          new_tree_range.start, new_tree_range.end); /* TODO: use path? */
    }
}

/**
 * block_set_add_updating_ranges - Write in-memory block set updates to tree
 * @tr:                     Transaction object.
 * @set:                    Block-set object.
 * @skip_last_inserting:    If %true skip the last entry in inserting_range.
 */
static void block_set_add_updating_ranges(struct transaction *tr,
                                          struct block_set *set,
                                          bool skip_last_inserting)
{
    bool removed;
    struct block_range range;
    int loop_limit = BLOCK_SET_MAX_DEPTH * BLOCK_SET_MAX_DEPTH * BLOCK_SET_MAX_DEPTH + tr->fs->dev->block_count;
    const int print_loop_limit = loop_limit - BLOCK_SET_MAX_DEPTH * BLOCK_SET_MAX_DEPTH * BLOCK_SET_MAX_DEPTH;

    while (true) {
        assert(loop_limit-- > 0);
        if (loop_limit == print_loop_limit) {
            printf("%s: near loop limit: updating set:\n", __func__);
            block_set_print(tr, set);
            printf("%s: free set:\n", __func__);
            block_set_print(tr, &tr->fs->free);
        }
        range = set->removing_range[0];
        if (!block_range_empty(range)) {
            array_shift_down(set->removing_range, 0, 1);
            if (loop_limit <= print_loop_limit) {
                pr_write("remove updating range [%lld-%lld]\n",
                         range.start, range.end - 1);
            }
            block_set_tree_remove_range(tr, set, range);
        } else {
            range = set->inserting_range[0];
            if (block_range_empty(range)) {
                return;
            }

            if (!skip_last_inserting || !block_range_empty(set->inserting_range[1])) {
                if (loop_limit <= print_loop_limit) {
                    pr_write("add updating range [%lld-%lld]\n",
                             range.start, range.end - 1);
                }
                block_set_tree_insert_range(tr, set, range);
            }

            removed = block_set_remove_inserted_range(set, range);
            if (!removed) {
                if (loop_limit <= print_loop_limit) {
                    pr_write("added updating range [%lld-%lld] gone, remove\n",
                             range.start, range.end - 1);
                }
                block_set_tree_remove_range(tr, set, range);
            }
        }
        if (tr->failed) {
            pr_warn("transaction failed, abort\n");
            return;
        }
    }
}

/**
 * block_set_add_range - Add a range to block set
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @range:      Block range to add.
 *
 * Add @range to @set. If @set is already updating, add @range to in-memory
 * updates and return, if not add @range to in-memory updates then update tree.
 */
void block_set_add_range(struct transaction *tr,
                         struct block_set *set,
                         struct block_range range)
{
    assert(!block_range_empty(range));

    if (tr->failed) {
        pr_warn("transaction failed, ignore\n");
        return;
    }

    full_assert(block_tree_check(tr, &set->block_tree));

    pr_write("set %lld, add %lld-%lld, updating %d\n",
             block_mac_to_block(tr, &set->block_tree.root),
             range.start, range.end - 1, set->updating);

    if (set->updating) {
        block_set_add_inserting_range(set, range);
        pr_write("set %lld, add %lld-%lld tmp insert done\n",
                 block_mac_to_block(tr, &set->block_tree.root),
                 range.start, range.end - 1);
    } else {
        set->updating = true;

        full_assert(block_set_check(tr, set));
        assert(block_set_range_not_in_set(tr, set, range));

        block_set_add_inserting_range(set, range); /* TODO: move up to common path? */
        block_set_tree_insert_range(tr, set, range); /* TODO: remove and use block_set_add_updating_ranges? */
        pr_write("set %lld, add %lld-%lld insert done\n",
                 block_mac_to_block(tr, &set->block_tree.root),
                 range.start, range.end - 1);

        if (tr->failed) {
            pr_warn("transaction failed, abort\n");
            return;
        }

        full_assert(block_set_check(tr, set));
        block_set_add_updating_ranges(tr, set, true);

        if (tr->failed) {
            pr_warn("transaction failed, abort\n");
            return;
        }

        assert(set->updating);
        set->updating = false;

        full_assert(block_set_check(tr, set));
        pr_write("set %lld, add %lld-%lld done\n",
                 block_mac_to_block(tr, &set->block_tree.root),
                 range.start, range.end - 1);
    }
}

/**
 * block_set_remove_range - Remove a range from block set
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @range:      Block range to add.
 *
 * Remove @range from @set. If @set is already updating, add @range to in-memory
 * updates and return, if not remove @range from tree then apply other updates
 * to tree if needed.
 */
void block_set_remove_range(struct transaction *tr,
                            struct block_set *set,
                            struct block_range range)
{
    assert(!block_range_empty(range));

    if (tr->failed) {
        pr_warn("transaction failed, ignore\n");
        return;
    }

    full_assert(block_tree_check(tr, &set->block_tree));

    pr_write("set %lld, remove %lld-%lld, updating %d\n",
             block_mac_to_block(tr, &set->block_tree.root),
             range.start, range.end - 1, set->updating);

    assert(block_set_range_in_set(tr, set, range) || tr->failed);

    if (set->updating) {
        block_set_add_removing_range(set, range);
        pr_write("set %lld, add %lld-%lld tmp remove done\n",
                 block_mac_to_block(tr, &set->block_tree.root),
                 range.start, range.end - 1);
    } else {
        set->updating = true;
        full_assert(block_set_check(tr, set));
        block_set_tree_remove_range(tr, set, range);

        if (tr->failed) {
            pr_warn("transaction failed, abort\n");
            return;
        }

        full_assert(block_set_check(tr, set));
        block_set_add_updating_ranges(tr, set, false);

        if (tr->failed) {
            pr_warn("transaction failed, abort\n");
            return;
        }

        assert(set->updating);
        set->updating = false;

        full_assert(block_set_check(tr, set));

        pr_write("set %lld, remove %lld-%lld done\n",
                 block_mac_to_block(tr, &set->block_tree.root),
                 range.start, range.end - 1);
    }
}

/**
 * block_set_add_block - Add block to block set
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @block:      Block to add.
 */
void block_set_add_block(struct transaction *tr,
                         struct block_set *set,
                         data_block_t block)
{
    struct block_range range;

    block_range_init_single(&range, block);
    block_set_add_range(tr, set, range);
}

/**
 * block_set_remove_block - Remove block from block set
 * @tr:         Transaction object.
 * @set:        Block-set object.
 * @block:      Block to remove.
 */
void block_set_remove_block(struct transaction *tr,
                            struct block_set *set,
                            data_block_t block)
{
    struct block_range range;

    block_range_init_single(&range, block);
    block_set_remove_range(tr, set, range);
}

/**
 * block_set_init - Initialize block set
 * @fs:         File system state object.
 * @set:        Block-set object.
 *
 * Clear block set, get block_num_size and mac_size from @fs and intialize
 * tree.
 */
void block_set_init(struct fs *fs, struct block_set *set)
{
    assert(fs);
    assert(fs->dev);

    memset(set, 0, sizeof(*set));
    block_tree_init(&set->block_tree,
                    fs->dev->block_size,
                    fs->block_num_size,
                    fs->block_num_size + fs->mac_size,
                    fs->block_num_size);
}

/**
 * block_set_add_initial_range - Add a range to an empty block set without updating tree
 * @set:        Block-set object.
 * @range:      Block range to add.
 *
 */
void block_set_add_initial_range(struct block_set *set,
                                 struct block_range range)
{
    assert(block_range_empty(set->inserting_range[0]));
    block_set_add_inserting_range(set, range);
}

/**
 * block_set_copy - Initialize a writable copy of a copy-on-write block set
 * @tr:         Transaction object.
 * @dest:       New writable block-set object.
 * @src:        Read-only block-set object.
 */
void block_set_copy(struct transaction *tr,
                    struct block_set *dest,
                    const struct block_set *src)
{
    assert(src->block_tree.copy_on_write);
    assert(!src->block_tree.allow_copy_on_write);

    block_set_init(tr->fs, dest);
    dest->block_tree.copy_on_write = true;
    dest->block_tree.allow_copy_on_write = true;
    dest->block_tree.root = src->block_tree.root;
    if (!block_mac_valid(tr, &dest->block_tree.root)) {
        /* special case for newly created empty fs */
        assert(!block_range_empty(src->inserting_range[0]));
        assert(block_range_empty(src->inserting_range[1]));
        dest->inserting_range[0] = src->inserting_range[0];
        dest->updating = true;
        block_set_add_updating_ranges(tr, dest, false);
        assert(dest->updating);
        dest->updating = false;
    } else {
        assert(block_range_empty(src->inserting_range[0]));
    }
}
