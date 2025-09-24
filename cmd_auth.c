/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_auth.c
#   Last Modified : 2025-07-24 11:06
#   Describe      : Auth Commands, updated for On-Demand Page Cache and Free Pages Bitmap
#
# ====================================================*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "db.h"
#include "config.h"
#include "utils.h"
#include "locker.h"
#include "stats.h"
#include "legacycc/common.h"
#include "cc2/common.h"

/*
 * Detect Command: Verifies the authenticity of a list of coins.
 */
void cmd_detect(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int coin_length, total_coins;
  uint32_t sn;
  int i;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  int p, f;
  int status;

  debug("CMD Detect");

  // Validate request size
  if (ci->body_size < 39)
  {
    error("Invalid command length: %d. Need 39", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 18;
  if (coin_length % 21)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 21;
  debug("Requested %d coins to auth. Shard %d", total_coins, ci->shard_id);

  ci->output = (unsigned char *)malloc((total_coins / 8) + 1);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }
  memset(ci->output, 0, (total_coins / 8) + 1);

  p = f = 0;

  // Handle different shards
  if (ci->shard_id == SHARD_CLOUDCOIN)
  {
    debug("CloudCoins v1 detect");
    status = legacy_detect(payload, total_coins, &p, &f, ci->output);
    if (status != STATUS_SUCCESS)
    {
      error("Failed to detect legacy coins");
      ci->command_status = status;
      return;
    }
  }
  else if (ci->shard_id == SHARD_SUPERCOIN)
  {
    debug("CloudCoins 2.0 detect");
    status = cc2_detect(payload, total_coins, &p, &f, ci->output);
    if (status != STATUS_SUCCESS)
    {
      error("Failed to detect coins 2.0");
      ci->command_status = status;
      return;
    }
  }
  else
  {
    // This is the main logic for the current RAIDAX system
    for (i = 0; i < total_coins; i++)
    {
      den = ((int8_t)payload[i * 21]);
      sn = get_sn(&payload[i * 21 + 1]);

      // ** NOTE: This function now uses the on-demand page cache. **
      // If the page is not in memory, it will be loaded from disk here.
      page = get_page_by_sn_lock(den, sn);
      if (page == NULL)
      {
        error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
        f++; // Count as failed if page can't be loaded
        continue;
      }

      sn_idx = sn % RECORDS_PER_PAGE;
      if (!memcmp(&page->data[sn_idx * 17], &payload[i * 21 + 5], 16))
      {
        debug("sn %d matches", sn);
        ci->output[i / 8] |= 1 << (i % 8);
        p++;
      }
      else
      {
        debug("sn %d does not match", sn);
        f++;
      }
      unlock_page(page);
    }
  }

  debug("Coins authentic/failed %d/%d of %d", p, f, total_coins);

  // Set the final response status
  if (p == total_coins)
  {
    ci->command_status = (char)STATUS_ALL_PASS;
  }
  else if (f == total_coins)
  {
    ci->command_status = (char)STATUS_ALL_FAIL;
  }
  else
  {
    ci->command_status = (char)STATUS_MIXED;
    ci->output_size = (total_coins / 8) + ((total_coins % 8) ? 1 : 0);
  }

  debug("CMD Detect finished");
}

/*
 * Detect Sum: Verifies the authenticity of a batch of coins by comparing an XOR sum.
 */
void cmd_detect_sum(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int coin_length, total_coins;
  uint32_t sn;
  int i, j;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  unsigned char xor[16];

  debug("CMD Detect Sum");

  // 16CH + (at least one DN + SN) = 5 + 16SU + 2EOF
  if (ci->body_size < 39)
  {
    error("Invalid command length: %d. Need 39", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 34;
  if (coin_length % 5)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 5;
  debug("Requested %d coins to auth via sum", total_coins);

  memset(xor, 0, 16);
  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[i * 5]);
    sn = get_sn(&payload[i * 5 + 1]);
    debug("den %hhx, SN %u", den, sn);
    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    for (j = 0; j < 16; j++)
    {
      xor[j] ^= page->data[sn_idx * 17 + j];
    }
    unlock_page(page);
  }

  if (!memcmp(xor, &payload[total_coins * 5], 16))
  {
    debug("Coins are authentic");
    ci->command_status = (char)STATUS_ALL_PASS;
  }
  else
  {
    debug("Coins are not authentic");
    ci->command_status = (char)STATUS_ALL_FAIL;
  }

  debug("CMD Detect Sum finished");
}

/*
 * Pown Command: Takes ownership of coins by changing their AN.
 */
void cmd_pown(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int coin_length, total_coins;
  uint32_t sn;
  int i;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  int p, f;
  uint8_t mfs;

  debug("CMD Pown");

  mfs = get_mfs();
  // 16CH + (at least one DN + SN + AN + PN) = 37 + 2EOF
  if (ci->body_size < 55)
  {
    error("Invalid command length: %d. Need 55", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 18;
  if (coin_length % 37)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 37;
  debug("Requested %d coins to pown", total_coins);

  ci->output = (unsigned char *)malloc((total_coins / 8) + 1);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }
  memset(ci->output, 0, (total_coins / 8) + 1);

  p = f = 0;
  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[i * 37]);
    sn = get_sn(&payload[i * 37 + 1]);

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      f++;
      continue;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    if (!memcmp(&page->data[sn_idx * 17], &payload[i * 37 + 5], 16))
    {
      debug("sn %u matches", sn);
      ci->output[i / 8] |= 1 << (i % 8);
      p++;

      // Update the AN to the new Proposed AN (PAN)
      debug("Setting PAN to %x %x %x ... %x", payload[i * 37 + 21], payload[i * 37 + 21 + 1], payload[i * 37 + 21 + 2], payload[i * 37 + 21 + 15]);
      memcpy(&page->data[sn_idx * 17], &payload[i * 37 + 21], 16);
      page->data[sn_idx * 17 + 16] = mfs;
      page->is_dirty = 1; // Mark page as dirty for persistence

      // ** NEW: Update the bitmap to mark this coin as 'not free' **
      update_free_pages_bitmap(den, sn, 0);

      inc_stat(POWN_FIELD_IDX, 1);
      inc_stat(POWN_VALUE_FIELD_IDX, get_den_value(den));
    }
    else
    {
      debug("sn %u does not match", sn);
      f++;
    }
    unlock_page(page);
  }
  debug("Coins authentic/failed %d/%d of %d", p, f, total_coins);

  if (p == total_coins)
    ci->command_status = (char)STATUS_ALL_PASS;
  else if (f == total_coins)
    ci->command_status = (char)STATUS_ALL_FAIL;
  else
  {
    ci->command_status = (char)STATUS_MIXED;
    ci->output_size = (total_coins + 7) / 8;
  }

  debug("CMD Pown finished");
}

/*
 * Pown Sum: Takes ownership of coins by applying a delta (XORing) to their ANs.
 */
void cmd_pown_sum(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int coin_length, total_coins;
  uint32_t sn;
  int i, j;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  unsigned char xor[16];
  uint8_t mfs;

  debug("CMD Pown Sum");

  mfs = get_mfs();

  if (ci->body_size < 55)
  {
    error("Invalid command length: %d. Need 55", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 50;
  if (coin_length % 5)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 5;
  debug("Requested %d coins to pown via sum", total_coins);

  memset(xor, 0, 16);
  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[i * 5]);
    sn = get_sn(&payload[i * 5 + 1]);

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    for (j = 0; j < 16; j++)
      xor[j] ^= page->data[sn_idx * 17 + j];
    unlock_page(page);
  }

  if (!memcmp(xor, &payload[total_coins * 5], 16))
  {
    debug("All SNs are authentic. Setting ANs");
    ci->command_status = (char)STATUS_ALL_PASS;
    unsigned char *ad = &payload[total_coins * 5 + 16];

    for (i = 0; i < total_coins; i++)
    {
      den = ((uint8_t)payload[i * 5]);
      sn = get_sn(&payload[i * 5 + 1]);

      page = get_page_by_sn_lock(den, sn);
      if (page == NULL)
      {
        error("Weird. We can't get the same page we got already. coin %d, sn %d -> %hhx", i, sn, den);
        ci->command_status = ERROR_INTERNAL;
        return;
      }

      sn_idx = sn % RECORDS_PER_PAGE;
      for (j = 0; j < 16; j++)
        page->data[sn_idx * 17 + j] ^= ad[j];
      page->data[sn_idx * 17 + 16] = mfs;
      page->is_dirty = 1; // Mark page as dirty for persistence

      // **  Update the bitmap to mark this coin as 'not free' **
      update_free_pages_bitmap(den, sn, 0);

      inc_stat(POWN_FIELD_IDX, 1);
      inc_stat(POWN_VALUE_FIELD_IDX, get_den_value(den));
      unlock_page(page);
    }
  }
  else
  {
    ci->command_status = (char)STATUS_ALL_FAIL;
  }

  debug("CMD Pown Sum finished");
}