/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_integrity.c
#   Last Modified : 2025-07-29 12:20
#   Describe      : Command handlers for the Merkle Tree Integrity Protocol.
#                 ** FIXED linker error by renaming function. **
#
# ====================================================*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "integrity.h"
#include "utils.h"
#include "db.h"
#include "config.h"

extern struct config_s config;

/**
 * @brief Handles a request from another server for a specific node in a Merkle Tree.

 */
void cmd_get_merkle_branch(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int8_t denomination;
  uint32_t level, index;
  unsigned char *branch_data;
  int branch_size;

  debug("CMD Get Merkle Branch received.");

  if (ci->body_size != 27)
  {
    error("Invalid body size for get_merkle_branch: %d", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  denomination = (int8_t)payload[0];
  level = get_u32(&payload[1]);
  index = get_u32(&payload[5]);
  uint32_t depth = 1;

  debug("Request for den: %d, level: %u, index: %u", denomination, level, index);

  if (get_merkle_branch(denomination, level, index, depth, &branch_data, &branch_size) != 0 || branch_size != HASH_SIZE)
  {
    error("Merkle node not found for den: %d, level: %u, index: %u", denomination, level, index);
    ci->command_status = ERROR_FILE_NOT_EXIST;
    return;
  }

  ci->output = branch_data;
  ci->output_size = branch_size;
  ci->command_status = STATUS_SUCCESS;

  debug("CMD Get Merkle Branch finished successfully.");
}

/**
 * @brief Handles a TCP request for all Merkle Tree root hashes.
 */
void cmd_get_all_roots(conn_info_t *ci)
{
  debug("CMD Get All Merkle Roots (TCP) received.");
  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }

  if (ci->body_size != 498)
  {
    error("Invalid body size for get_all_roots TCP command: %d. Expected 498.", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  ci->output_size = TOTAL_DENOMINATIONS * HASH_SIZE;
  ci->output = malloc(ci->output_size);
  if (!ci->output)
  {
    error("Failed to allocate memory for all roots response.");
    ci->command_status = ERROR_MEMORY_ALLOC;
    ci->output_size = 0;
    return;
  }

  for (int i = 0; i < TOTAL_DENOMINATIONS; i++)
  {
    int8_t den = get_den_by_idx(i);
    if (get_merkle_root(den, ci->output + (i * HASH_SIZE)) != 0)
    {
      memset(ci->output + (i * HASH_SIZE), 0, HASH_SIZE);
    }
  }

  ci->command_status = STATUS_SUCCESS;
  debug("CMD Get All Merkle Roots (TCP) finished successfully.");
}

/**
 * @brief Handles a request for the raw data of a specific page.
 */
void cmd_get_page_data(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int8_t denomination;
  uint32_t page_no;
  char page_path[PATH_MAX];
  int fd;

  debug("CMD Get Page Data received.");

  if (ci->body_size != (16 + 5 + 2))
  {
    error("Invalid body size for get_page_data: %d", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  denomination = (int8_t)payload[0];
  page_no = get_u32(&payload[1]);
  debug("Request for page data: den %d, page_no %u", denomination, page_no);

  ci->output_size = RECORDS_PER_PAGE * 17;
  ci->output = malloc(ci->output_size);
  if (!ci->output)
  {
    error("Failed to allocate memory for page data response.");
    ci->command_status = ERROR_MEMORY_ALLOC;
    ci->output_size = 0;
    return;
  }

  uint8_t page_msb = (page_no >> 8) & 0xff;
  snprintf(page_path, sizeof(page_path), "%s/Data/%02hhx/%02x/%04x.bin", config.cwd, (uint8_t)denomination, page_msb, page_no);

  fd = open(page_path, O_RDONLY);
  if (fd < 0)
  {
    error("Failed to open page file %s for reading: %s", page_path, strerror(errno));
    ci->command_status = ERROR_FILE_NOT_EXIST;
    free(ci->output);
    ci->output = NULL;
    ci->output_size = 0;
    return;
  }

  ssize_t bytes_read = read(fd, ci->output, ci->output_size);
  close(fd);

  if (bytes_read != ci->output_size)
  {
    error("Failed to read complete page file %s", page_path);
    ci->command_status = ERROR_FILESYSTEM;
    free(ci->output);
    ci->output = NULL;
    ci->output_size = 0;
    return;
  }

  ci->command_status = STATUS_SUCCESS;
  debug("CMD Get Page Data finished successfully.");
}
