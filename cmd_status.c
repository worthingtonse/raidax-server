/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_status.c
#   Last Modified : 2025-07-29 12:05
#   Describe      : Status commands, updated for On-Demand Page Cache.
#                 ** FIXED missing header include. **
#
# ====================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "main.h"
#include "db.h"
#include "stats.h"
#include "config.h"
#include "ht.h"
#include "utils.h"

extern struct stats_s stats;
extern pthread_mutex_t stats_mtx;
extern struct config_s config;

/*
 * Echo Command: A simple health check command.
 */
void cmd_echo(conn_info_t *ci)
{
  debug("CMD Echo Started");

  ci->output_size = 0;
  ci->command_status = (char)STATUS_SUCCESS;

  inc_stat(ECHO_FIELD_IDX, 1);

  debug("CMD Echo Finished");
}

/*
 * Version Command: Returns the server's build version.
 */
void cmd_version(conn_info_t *ci)
{
  debug("CMD Version");

  ci->output = (unsigned char *)malloc(8);
  if (ci->output == NULL)
  {
    ci->command_status = ERROR_MEMORY_ALLOC;
    ci->output_size = 0;
    return;
  }
  ci->output_size = 8;

  memcpy(ci->output, VERSION, 8);
  ci->command_status = (char)STATUS_SUCCESS;
}

/*
 * ** REWRITTEN for On-Demand Cache **
 * Audit service returns the number of issued coins per a denomination.
 * This function now reads page files directly from disk to avoid polluting the cache.
 */
void cmd_audit(conn_info_t *ci)
{
  int output_idx;
  uint32_t count;
  int i, j, k;
  uint8_t mfs;
  char page_path[PATH_MAX];
  unsigned char page_buffer[RECORDS_PER_PAGE * 17];
  int fd;

  debug("CMD %s Started", __func__);

  ci->output_size = TOTAL_DENOMINATIONS * 4;
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    error("Failed to allocate memory for audit response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    ci->output_size = 0;
    return;
  }

  output_idx = 0;
  for (i = MIN_DENOMINATION; i <= MAX_DENOMINATION; i++)
  {
    count = 0;

    // ** PERFORMANCE OPTIMIZATION **
    // Iterate through all possible page files for the denomination directly on disk.
    for (j = 0; j < TOTAL_PAGES; j++)
    {
      uint8_t page_msb = (j >> 8) & 0xff;
      snprintf(page_path, sizeof(page_path), "%s/Data/%02hhx/%02x/%04x.bin", config.cwd, (uint8_t)i, page_msb, j);

      fd = open(page_path, O_RDONLY);
      if (fd < 0)
      {
        // This is not necessarily an error; page files might not exist if never used.
        continue;
      }

      if (read(fd, page_buffer, sizeof(page_buffer)) != sizeof(page_buffer))
      {
        error("Failed to read full page file for audit: %s", page_path);
        close(fd);
        continue;
      }
      close(fd);

      // Count the coins in circulation from the buffer we read from disk
      for (k = 0; k < RECORDS_PER_PAGE; k++)
      {
        mfs = page_buffer[k * 17 + 16];
        if (mfs != 0)
        {
          count++;
        }
      }
    }

    debug("den %d count %u", i, count);

    // Write the result for this denomination to the output buffer
    ci->output[output_idx++] = i;
    put_u32(count, &ci->output[output_idx]);
    output_idx += 3; // put_u32 writes 4 bytes, but we only increment by 3 because the loop will increment by 1

    // Correction for the loop increment
    if (output_idx > 0 && i != MAX_DENOMINATION)
    {
      output_idx++;
    }
  }

  // Adjust final output size
  ci->output_size = output_idx;
  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD %s Finished", __func__);
}

/*
 * ShowStats service returns collected metrics.
 */
void cmd_show_stats(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);

  debug("CMD %s Started", __func__);

  // Check auth
  if (memcmp(&payload[0], config.admin_key, 16) != 0)
  {
    error("Failed to check auth. Invalid key for show_stats.");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  ci->output_size = sizeof(struct stats_s);
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    error("Failed to allocate memory for stats response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    ci->output_size = 0;
    return;
  }

  copy_stats(ci->output);

  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD %s Finished", __func__);
}
