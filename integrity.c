/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : integrity.c
#   Last Modified : 2025-07-23 11:25
#   Describe      : Merkle Tree Integrity System with Selective Hashing
#                 ** FIXED critical bug in TCP request logic for healing. **
#
# ====================================================*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <math.h>
#include <sys/select.h>
#include <stdbool.h>

#include "config.h"
#include "db.h"
#include "log.h"
#include "integrity.h"
#include "utils.h"
#include "protocol.h"

extern struct config_s config;
extern int is_finished;

// --- Global Variables for the Integrity System ---
static merkle_tree_t *merkle_tree_cache[TOTAL_DENOMINATIONS];
static pthread_mutex_t merkle_tree_locks[TOTAL_DENOMINATIONS];
static pthread_t sync_thread_handle;
// A flag to track if the thread was successfully started
static bool sync_thread_started = false;

// --- Forward Declarations for Internal Functions ---
static void hash_data(const unsigned char *data1, int len1, const unsigned char *data2, int len2, unsigned char *out_hash);
static int send_udp_vote_request(int raida_idx, unsigned char *my_roots);
static int send_tcp_integrity_request(int raida_idx, int command, unsigned char *body, int body_len, unsigned char **response_body, int *response_len);
static void heal_page(int8_t denomination, int page_no, int trusted_raida_idx);
static void find_and_heal_discrepancies(int8_t den, int trusted_peer, unsigned char *majority_roots);

/**
 * @brief Initializes the integrity system.
 */
int init_integrity_system(void)
{
  pthread_t sync_thread;
  debug("Initializing Merkle Tree Integrity System.");

  if (!config.synchronization_enabled)
  {
    warning("Merkle Tree Synchronization is DISABLED in the config file.");
    sync_thread_started = false; // Ensure flag is false
    return 0;
  }

  for (int i = 0; i < TOTAL_DENOMINATIONS; i++)
  {
    merkle_tree_cache[i] = NULL;
    if (pthread_mutex_init(&merkle_tree_locks[i], NULL) != 0)
    {
      error("Failed to initialize Merkle Tree mutex for denomination index %d", i);
      return -1;
    }
  }
  if (pthread_create(&sync_thread_handle, NULL, merkle_sync_thread, NULL) < 0)
  {
    error("Failed to start Merkle sync thread: %s", strerror(errno));
    sync_thread_started = false; // Ensure flag is false
    return -1;
  }
  sync_thread_started = true;
  debug("Merkle Tree Synchronization is ENABLED.");
  return 0;
}

/**
 * @brief The main background thread that periodically rebuilds Merkle Trees and performs self-healing.
 */
void *merkle_sync_thread(void *arg)
{
  debug("Merkle sync thread started.");
  while (!is_finished)
  {
    sleep(config.integrity_freq);
    if (is_finished)
      break;

    debug("Starting periodic Merkle Tree rebuild and integrity check cycle.");

    for (int i = 0; i < TOTAL_DENOMINATIONS; i++)
    {
      int8_t den = get_den_by_idx(i);
      merkle_tree_t *new_tree = build_merkle_tree_for_denomination(den);

      pthread_mutex_lock(&merkle_tree_locks[i]);
      if (merkle_tree_cache[i])
        free_merkle_tree(merkle_tree_cache[i]);
      merkle_tree_cache[i] = new_tree;
      pthread_mutex_unlock(&merkle_tree_locks[i]);
    }

    unsigned char my_all_roots[TOTAL_DENOMINATIONS * HASH_SIZE];
    bool local_roots_ok = true;
    for (int i = 0; i < TOTAL_DENOMINATIONS; i++)
    {
      if (get_merkle_root(get_den_by_idx(i), &my_all_roots[i * HASH_SIZE]) != 0)
      {
        error("Could not get local root for den idx %d, skipping integrity cycle.", i);
        local_roots_ok = false;
        break;
      }
    }
    if (!local_roots_ok)
    {
      continue;
    }

    debug("Integrity Check Stage 1: UDP Quick Vote.");
    int match_votes = 0;
    int no_match_votes = 0;
    int no_match_peers[TOTAL_RAIDA_SERVERS];

    for (int r_idx = 0; r_idx < TOTAL_RAIDA_SERVERS; r_idx++)
    {
      if (r_idx == config.raida_no)
        continue;

      int vote_result = send_udp_vote_request(r_idx, my_all_roots);

      if (vote_result == 1)
      {
        match_votes++;
      }
      else if (vote_result == 0)
      {
        no_match_peers[no_match_votes] = r_idx;
        no_match_votes++;
      }
    }
    debug("UDP Vote Results: %d Match, %d No Match.", match_votes, no_match_votes);

    if (match_votes >= (TOTAL_RAIDA_SERVERS / 2))
    {
      debug("Integrity check passed. Local data matches network majority. Cycle complete.");
      continue;
    }

    debug("Local data is in the minority. Proceeding to Stage 2.");

    debug("Integrity Check Stage 2: TCP Ballot Collection.");

    unsigned char **peer_root_ballots = malloc(sizeof(unsigned char *) * no_match_votes);
    if (!peer_root_ballots)
    {
      error("Failed to allocate memory for peer root ballots.");
      continue;
    }
    int valid_ballots = 0;

    for (int i = 0; i < no_match_votes; i++)
    {
      int peer_idx = no_match_peers[i];
      unsigned char *resp_body = NULL;
      int resp_len = 0;

      // ** FIX: Call the refactored function with correct command and body length **
      if (send_tcp_integrity_request(peer_idx, 5, my_all_roots, TOTAL_DENOMINATIONS * HASH_SIZE, &resp_body, &resp_len) == 0 && resp_len == TOTAL_DENOMINATIONS * HASH_SIZE)
      {
        peer_root_ballots[valid_ballots] = resp_body;
        valid_ballots++;
      }
      else
      {
        error("Failed to collect ballot from RAIDA %d via TCP.", peer_idx);
        if (resp_body)
          free(resp_body);
      }
    }

    if (valid_ballots < (TOTAL_RAIDA_SERVERS / 2))
    {
      error("Could not collect enough ballots to determine a true majority. Aborting heal.");
    }
    else
    {
      unsigned char *majority_roots = NULL;
      int max_votes = 0;

      for (int i = 0; i < valid_ballots; i++)
      {
        int current_votes = 1;
        for (int j = i + 1; j < valid_ballots; j++)
        {
          if (memcmp(peer_root_ballots[i], peer_root_ballots[j], TOTAL_DENOMINATIONS * HASH_SIZE) == 0)
          {
            current_votes++;
          }
        }
        if (current_votes > max_votes)
        {
          max_votes = current_votes;
          majority_roots = peer_root_ballots[i];
        }
      }

      if (majority_roots)
      {
        debug("True majority found. Initiating healing process.");
        int trusted_peer = -1;
        for (int i = 0; i < no_match_votes; i++)
        {
          if (memcmp(peer_root_ballots[i], majority_roots, TOTAL_DENOMINATIONS * HASH_SIZE) == 0)
          {
            trusted_peer = no_match_peers[i];
            break;
          }
        }

        if (trusted_peer != -1)
        {
          for (int den_idx = 0; den_idx < TOTAL_DENOMINATIONS; den_idx++)
          {
            if (memcmp(&my_all_roots[den_idx * HASH_SIZE], &majority_roots[den_idx * HASH_SIZE], HASH_SIZE) != 0)
            {
              int8_t den_to_heal = get_den_by_idx(den_idx);
              debug("Healing denomination %d from trusted peer RAIDA %d", den_to_heal, trusted_peer);
              find_and_heal_discrepancies(den_to_heal, trusted_peer, majority_roots);
            }
          }
        }
      }
      else
      {
        error("No clear majority found among disagreeing peers. Aborting heal.");
      }
    }

    for (int i = 0; i < valid_ballots; i++)
      free(peer_root_ballots[i]);
    free(peer_root_ballots);

    debug("Integrity check cycle finished.");
  }
  debug("Merkle sync thread shutting down.");
  return NULL;
}

/**
 * @brief Iteratively walks a Merkle tree to find all corrupt pages and heals them.
 */
static void find_and_heal_discrepancies(int8_t den, int trusted_peer, unsigned char *majority_roots)
{
  int den_idx = get_den_idx(den);
  pthread_mutex_lock(&merkle_tree_locks[den_idx]);
  merkle_tree_t *my_tree = merkle_tree_cache[den_idx];
  if (!my_tree)
  {
    pthread_mutex_unlock(&merkle_tree_locks[den_idx]);
    return;
  }

  typedef struct
  {
    int level;
    int index;
  } node_to_check;
  node_to_check *queue = malloc(sizeof(node_to_check) * my_tree->leaf_count * 2);
  if (!queue)
  {
    error("Failed to allocate memory for tree traversal queue.");
    pthread_mutex_unlock(&merkle_tree_locks[den_idx]);
    return;
  }
  int head = 0, tail = 0;
  queue[tail++] = (node_to_check){my_tree->num_levels - 1, 0};

  while (head < tail)
  {
    node_to_check current = queue[head++];
    unsigned char *my_hash = my_tree->levels[current.level][current.index];
    unsigned char req_body[9];
    unsigned char *peer_node_hash_body;
    int peer_node_size;

    req_body[0] = den;
    put_u32(current.level, &req_body[1]);
    put_u32(current.index, &req_body[5]);

    // ** FIX: Call the refactored function with correct command and body length **
    if (send_tcp_integrity_request(trusted_peer, 2, req_body, sizeof(req_body), &peer_node_hash_body, &peer_node_size) != 0 || peer_node_size != HASH_SIZE)
    {
      if (peer_node_hash_body)
        free(peer_node_hash_body);
      continue;
    }

    if (memcmp(my_hash, peer_node_hash_body, HASH_SIZE) != 0)
    {
      if (current.level == 0)
      {
        heal_page(den, current.index, trusted_peer);
      }
      else
      {
        queue[tail++] = (node_to_check){current.level - 1, current.index * 2};
        int nodes_in_child_level = (my_tree->leaf_count + (1 << (current.level - 1)) - 1) / (1 << (current.level - 1));
        if ((current.index * 2 + 1) < nodes_in_child_level)
        {
          queue[tail++] = (node_to_check){current.level - 1, current.index * 2 + 1};
        }
      }
    }
    free(peer_node_hash_body);
  }
  free(queue);
  pthread_mutex_unlock(&merkle_tree_locks[den_idx]);
}

/**
 * @brief Heals a specific page by fetching the correct data from a trusted peer.
 */
static void heal_page(int8_t denomination, int page_no, int trusted_raida_idx)
{
  unsigned char req_body[5];
  unsigned char *resp_body;
  int resp_len;
  char page_path[PATH_MAX];
  int fd;

  debug("Healing page %d for denomination %d from RAIDA %d.", page_no, denomination, trusted_raida_idx);

  req_body[0] = denomination;
  put_u32(page_no, &req_body[1]);

  // ** FIX: Call the refactored function with correct command and body length **
  if (send_tcp_integrity_request(trusted_raida_idx, 4, req_body, sizeof(req_body), &resp_body, &resp_len) != 0 || resp_len != (RECORDS_PER_PAGE * 17))
  {
    error("Failed to fetch correct page data for healing.");
    if (resp_body)
      free(resp_body);
    return;
  }

  uint8_t page_msb = (page_no >> 8) & 0xff;
  snprintf(page_path, sizeof(page_path), "%s/Data/%02hhx/%02x/%04x.bin", config.cwd, (uint8_t)denomination, page_msb, page_no);

  fd = open(page_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
  {
    error("Failed to open local page file for writing: %s", strerror(errno));
    free(resp_body);
    return;
  }

  if (write(fd, resp_body, resp_len) != resp_len)
  {
    error("Failed to write healed data to page file: %s", strerror(errno));
  }
  else
  {
    debug("Successfully healed page %d for denomination %d.", page_no, denomination);
  }

  close(fd);
  free(resp_body);
}

/**
 * @brief Sends a UDP request to a RAIDA peer to get a "match" or "no match" vote.
 * @return 1 for match, 0 for no match, -1 for error/timeout.
 */
static int send_udp_vote_request(int raida_idx, unsigned char *my_roots)
{
  int sk;
  unsigned char request_buf[1 + (TOTAL_DENOMINATIONS * HASH_SIZE) + 16];
  unsigned char response_buf[1 + 16];
  unsigned char nonce[16];

  if (generate_random_bytes(nonce, 16) != 0)
    return -1;

  request_buf[0] = 7;
  memcpy(&request_buf[1], my_roots, TOTAL_DENOMINATIONS * HASH_SIZE);
  memcpy(&request_buf[1 + TOTAL_DENOMINATIONS * HASH_SIZE], nonce, 16);

  sk = socket(AF_INET, SOCK_DGRAM, 0);
  if (sk < 0)
    return -1;

  struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
  setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

  if (sendto(sk, request_buf, sizeof(request_buf), 0, config.raida_addrs[raida_idx], sizeof(struct sockaddr)) < 0)
  {
    close(sk);
    return -1;
  }

  ssize_t bytes_received = recvfrom(sk, response_buf, sizeof(response_buf), 0, NULL, NULL);
  close(sk);

  if (bytes_received != sizeof(response_buf))
    return -1;
  if (memcmp(&response_buf[1], nonce, 16) != 0)
    return -1;

  return (int)response_buf[0];
}

/**
 * @brief Sends a generic TCP request to another RAIDA server for integrity operations.
 * ** FIX: This function is now flexible and accepts the command and body_len as arguments. **
 */
static int send_tcp_integrity_request(int raida_idx, int command, unsigned char *body, int body_len, unsigned char **response_body, int *response_len)
{
  int sk;
  unsigned char *request_buf;
  unsigned char response_header[RESPONSE_HEADER_SIZE];

  sk = socket(AF_INET, SOCK_STREAM, 0);
  if (sk < 0)
    return -1;

  struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
  setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

  if (connect(sk, config.raida_addrs[raida_idx], sizeof(struct sockaddr)) < 0)
  {
    close(sk);
    return -1;
  }

  int total_body_size = 16 + body_len + 2;
  int total_request_size = REQUEST_HEADER_SIZE + total_body_size;
  request_buf = malloc(total_request_size);
  if (!request_buf)
  {
    close(sk);
    return -1;
  }

  memset(request_buf, 0, total_request_size);
  request_buf[2] = raida_idx;
  request_buf[4] = 14; // INTEGRITY command group
  request_buf[5] = command;
  request_buf[22] = (total_body_size >> 8) & 0xff;
  request_buf[23] = total_body_size & 0xff;

  generate_random_bytes(&request_buf[REQUEST_HEADER_SIZE], 12);
  uint32_t crc = crc32b(&request_buf[REQUEST_HEADER_SIZE], 12);
  put_u32(crc, &request_buf[REQUEST_HEADER_SIZE + 12]);

  if (body && body_len > 0)
  {
    memcpy(&request_buf[REQUEST_HEADER_SIZE + 16], body, body_len);
  }

  request_buf[REQUEST_HEADER_SIZE + 16 + body_len] = 0x3e;
  request_buf[REQUEST_HEADER_SIZE + 16 + body_len + 1] = 0x3e;

  if (send(sk, request_buf, total_request_size, 0) < 0)
  {
    free(request_buf);
    close(sk);
    return -1;
  }
  free(request_buf);

  if (recv(sk, response_header, RESPONSE_HEADER_SIZE, MSG_WAITALL) != RESPONSE_HEADER_SIZE)
  {
    close(sk);
    return -1;
  }

  if (response_header[2] != STATUS_SUCCESS)
  {
    close(sk);
    return -1;
  }

  *response_len = (response_header[9] << 16) | (response_header[10] << 8) | response_header[11];
  if (*response_len >= 2)
    *response_len -= 2;
  else
    *response_len = 0;

  if (*response_len > 0)
  {
    *response_body = malloc(*response_len);
    if (!*response_body)
    {
      close(sk);
      return -1;
    }
    if (recv(sk, *response_body, *response_len, MSG_WAITALL) != *response_len)
    {
      free(*response_body);
      *response_body = NULL;
      close(sk);
      return -1;
    }
  }
  else
  {
    *response_body = NULL;
  }

  unsigned char trailer[2];
  recv(sk, trailer, 2, MSG_WAITALL);
  close(sk);
  return 0;
}

/**
 * @brief Builds a Merkle Tree using the "Selective Hashing" method.
 */
merkle_tree_t *build_merkle_tree_for_denomination(int8_t denomination)
{
  char page_path[PATH_MAX];
  unsigned char page_buffer[RECORDS_PER_PAGE * 17];
  unsigned char standardized_buffer[RECORDS_PER_PAGE * 16];
  int fd;

  unsigned char (*leaf_hashes)[HASH_SIZE] = malloc(TOTAL_PAGES * HASH_SIZE);
  if (!leaf_hashes)
    return NULL;

  int leaf_count = 0;
  for (int i = 0; i < TOTAL_PAGES; i++)
  {
    uint8_t page_msb = (i >> 8) & 0xff;
    snprintf(page_path, sizeof(page_path), "%s/Data/%02hhx/%02x/%04x.bin", config.cwd, (uint8_t)denomination, page_msb, i);
    fd = open(page_path, O_RDONLY);
    if (fd < 0 || read(fd, page_buffer, sizeof(page_buffer)) != sizeof(page_buffer))
    {
      memset(leaf_hashes[leaf_count++], 0, HASH_SIZE);
      if (fd >= 0)
        close(fd);
      continue;
    }
    close(fd);

    for (int j = 0; j < RECORDS_PER_PAGE; j++)
    {
      uint8_t mfs = page_buffer[j * 17 + 16];
      if (mfs != 0)
      {
        memcpy(&standardized_buffer[j * 16], &page_buffer[j * 17], 16);
      }
      else
      {
        memset(&standardized_buffer[j * 16], 0, 16);
      }
    }
    hash_data(standardized_buffer, sizeof(standardized_buffer), NULL, 0, leaf_hashes[leaf_count++]);
  }

  if (leaf_count == 0)
  {
    free(leaf_hashes);
    return NULL;
  }

  int num_levels = (int)ceil(log2(leaf_count)) + 1;
  merkle_tree_t *tree = malloc(sizeof(merkle_tree_t));
  if (!tree)
  {
    free(leaf_hashes);
    return NULL;
  }

  tree->levels = malloc(sizeof(unsigned char **) * num_levels);
  if (!tree->levels)
  {
    free(leaf_hashes);
    free(tree);
    return NULL;
  }

  tree->num_levels = num_levels;
  tree->leaf_count = leaf_count;

  tree->levels[0] = malloc(sizeof(unsigned char *) * leaf_count);
  if (!tree->levels[0])
  {
    free(leaf_hashes);
    free(tree->levels);
    free(tree);
    return NULL;
  }

  for (int i = 0; i < leaf_count; i++)
  {
    tree->levels[0][i] = malloc(HASH_SIZE);
    if (!tree->levels[0][i])
    {
      free(leaf_hashes);
      free_merkle_tree(tree);
      return NULL;
    }
    memcpy(tree->levels[0][i], leaf_hashes[i], HASH_SIZE);
  }
  free(leaf_hashes);

  int nodes_in_level = leaf_count;
  for (int level = 1; level < num_levels; level++)
  {
    int nodes_in_next_level = (nodes_in_level + 1) / 2;
    tree->levels[level] = malloc(sizeof(unsigned char *) * nodes_in_next_level);
    if (!tree->levels[level])
    {
      free_merkle_tree(tree);
      return NULL;
    }

    for (int i = 0; i < nodes_in_next_level; i++)
    {
      tree->levels[level][i] = malloc(HASH_SIZE);
      if (!tree->levels[level][i])
      {
        free_merkle_tree(tree);
        return NULL;
      }

      unsigned char *left = tree->levels[level - 1][i * 2];
      unsigned char *right = (i * 2 + 1 < nodes_in_level) ? tree->levels[level - 1][i * 2 + 1] : left;
      hash_data(left, HASH_SIZE, right, HASH_SIZE, tree->levels[level][i]);
    }
    nodes_in_level = nodes_in_next_level;
  }
  return tree;
}

int get_merkle_root(int8_t denomination, unsigned char *root_hash_out)
{
  int den_idx = get_den_idx(denomination);
  pthread_mutex_lock(&merkle_tree_locks[den_idx]);
  merkle_tree_t *tree = merkle_tree_cache[den_idx];
  int result = -1;
  if (tree && tree->num_levels > 0)
  {
    memcpy(root_hash_out, tree->levels[tree->num_levels - 1][0], HASH_SIZE);
    result = 0;
  }
  pthread_mutex_unlock(&merkle_tree_locks[den_idx]);
  return result;
}

int get_merkle_branch(int8_t denomination, int level, int index, int depth, unsigned char **branch_data, int *branch_size)
{
  int den_idx = get_den_idx(denomination);
  pthread_mutex_lock(&merkle_tree_locks[den_idx]);
  merkle_tree_t *tree = merkle_tree_cache[den_idx];
  int result = -1;
  *branch_size = 0;

  if (tree && level < tree->num_levels)
  {
    int total_size = 0;
    for (int d = 0; d < depth && (level - d) >= 0; d++)
    {
      int current_level = level - d;
      int start_index = index * (1 << d);
      int end_index = (index + 1) * (1 << d);
      int nodes_in_level = (tree->leaf_count + (1 << current_level) - 1) / (1 << current_level);
      if (end_index > nodes_in_level)
        end_index = nodes_in_level;
      total_size += (end_index - start_index) * HASH_SIZE;
    }

    *branch_data = malloc(total_size);
    if (*branch_data)
    {
      int offset = 0;
      for (int d = 0; d < depth && (level - d) >= 0; d++)
      {
        int current_level = level - d;
        int start_index = index * (1 << d);
        int end_index = (index + 1) * (1 << d);
        int nodes_in_level = (tree->leaf_count + (1 << current_level) - 1) / (1 << current_level);
        if (end_index > nodes_in_level)
          end_index = nodes_in_level;

        for (int i = start_index; i < end_index; i++)
        {
          memcpy(*branch_data + offset, tree->levels[current_level][i], HASH_SIZE);
          offset += HASH_SIZE;
        }
      }
      *branch_size = total_size;
      result = 0;
    }
  }
  pthread_mutex_unlock(&merkle_tree_locks[den_idx]);
  return result;
}

void free_merkle_tree(merkle_tree_t *tree)
{
  if (!tree)
    return;
  if (tree->levels)
  {
    for (int level = 0; level < tree->num_levels; level++)
    {
      if (tree->levels[level])
      {
        int nodes_this_level = (tree->leaf_count + (1 << level) - 1) / (1 << level);
        for (int i = 0; i < nodes_this_level; i++)
        {
          if (tree->levels[level][i])
          {
            free(tree->levels[level][i]);
          }
        }
        free(tree->levels[level]);
      }
    }
    free(tree->levels);
  }
  free(tree);
}

static void hash_data(const unsigned char *data1, int len1, const unsigned char *data2, int len2, unsigned char *out_hash)
{
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, data1, len1);
  if (data2 && len2 > 0)
  {
    SHA256_Update(&sha256, data2, len2);
  }
  SHA256_Final(out_hash, &sha256);
}

void cleanup_integrity_threads(void)
{
  debug("Shutting down integrity sync thread...");
  // ** FIXED: Only join the thread if it was actually started **
  if (sync_thread_started)
  {
    if (pthread_join(sync_thread_handle, NULL) != 0)
    {
      error("Failed to join sync thread");
    }
  }
  debug("Integrity sync thread shut down cleanly.");
}
