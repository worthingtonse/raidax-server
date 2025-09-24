/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : integrity.h
#   Last Modified : 2025-01-14 11:30
#   Describe      : Merkle Tree Integrity System Header
#
# ====================================================*/

#ifndef _INTEGRITY_H
#define _INTEGRITY_H

#include <pthread.h>
#include <stdint.h>
#include "db.h" // For TOTAL_DENOMINATIONS

// We will use SHA-256 for our Merkle Tree, which produces a 32-byte hash.
#define HASH_SIZE 32

// Represents the complete Merkle Tree for a single denomination.
// This structure holds pointers to arrays of hashes for each level of the tree.
typedef struct
{
  unsigned char ***levels; // A 2D array of hashes: levels[level][node_index]
  int num_levels;          // The total number of levels in the tree.
  int leaf_count;          // The number of leaf nodes (pages) in this tree.
} merkle_tree_t;

// --- Public Functions ---

/**
 * @brief Initializes the integrity system and starts the background synchronization thread.
 * @return 0 on success, -1 on failure.
 */
int init_integrity_system(void);

/**
 * @brief The main function for the background thread that periodically builds the Merkle Trees
 * and synchronizes with other RAIDA servers.
 * @param arg Thread argument (unused).
 * @return NULL.
 */
void *merkle_sync_thread(void *arg);

/**
 * @brief Retrieves the root hash of the Merkle Tree for a given denomination.
 * This is used by other servers to quickly check for consistency.
 * @param denomination The denomination to get the root for.
 * @param root_hash_out A buffer of HASH_SIZE to store the resulting root hash.
 * @return 0 on success, -1 if the tree for the denomination doesn't exist.
 */
int get_merkle_root(int8_t denomination, unsigned char *root_hash_out);

/**
 * @brief Retrieves a branch of the Merkle Tree. This is an optimization to fetch
 * multiple related nodes at once.
 * @param denomination The denomination of the tree.
 * @param level The starting level of the branch.
 * @param index The starting index of the branch at that level.
 * @param depth The number of levels to fetch downwards from the start.
 * @param branch_data A pointer that will be allocated to store the resulting hash data.
 * @param branch_size A pointer to store the size of the allocated branch data.
 * @return 0 on success, -1 on failure.
 */
int get_merkle_branch(int8_t denomination, int level, int index, int depth, unsigned char **branch_data, int *branch_size);

// --- Internal Functions (defined in integrity.c) ---

/**
 * @brief Builds a complete Merkle Tree for a single denomination by hashing all its pages.
 * @param denomination The denomination to build the tree for.
 * @return A pointer to the newly created Merkle Tree, or NULL on failure.
 */
merkle_tree_t *build_merkle_tree_for_denomination(int8_t denomination);

/**
 * @brief Frees all memory associated with a Merkle Tree, including all its nodes.
 * @param tree A pointer to the Merkle Tree to be freed.
 */
void free_merkle_tree(merkle_tree_t *tree);
void cleanup_integrity_threads(void);

#endif // _INTEGRITY_H
