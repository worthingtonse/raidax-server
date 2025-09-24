/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_shards.c
#   Last Modified : 2025-07-24 11:12
#   Describe      : Shard commands, updated for dual hashing support and Free Pages Bitmap.
#
# ====================================================*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "db.h"
#include "md5.h"
#include "utils.h"
#include "legacycc/common.h"
#include "cc2/common.h"
#include "stats.h"
#include "config.h"

extern struct config_s config;

// Return no more than this number of coins per denomination
#define MAX_AVAILABLE_COINS 1024

/*
 * The client can roll back a failed transaction.
 * NOTE: This function is a stub in the original code and remains so.
 */
void cmd_rollback_switch_shard(conn_info_t *ci)
{
  debug("CMD %s Started", __func__);
  ci->command_status = ERROR_NOT_IMPLEMENTED;
  debug("CMD %s Finished", __func__);
}

/*
 * Gets available SNs from the existing pages for a shard switch operation.
 */
void cmd_get_sns(conn_info_t *ci)
{
  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int i, j, k;
  int8_t den;
  int ri;
  int den_idx;
  struct page_s *page;
  uint8_t mfs;
  int rcnt, scnt, ridx, tmp_cnt;
  int start, end;
  int output_idx;
  int individual_sn_output_idx;
  uint32_t si;
  uint32_t tmp_individual_sns[MAX_AVAILABLE_COINS];
  uint32_t tmp_ranges_sns[MAX_AVAILABLE_COINS * 2];
  uint8_t done;
  int op;
  unsigned char dens[16];

  debug("CMD %s Started", __func__);

  // 16CH + 4SI + 1OP + + 16DN +2EOF
  if (ci->body_size != 39)
  {
    error("Invalid command length: %d. Need 39", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  si = get_u32(payload);
  debug("Session ID %x", si);

  op = payload[4];
  debug("Op %d", op);

  if (op != 3 && op != 4)
  {
    error("Invalid op");
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  memcpy(dens, &payload[5], 16);
  debug("dens %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
        dens[0], dens[1], dens[2], dens[3], dens[4], dens[5], dens[6], dens[7], dens[8],
        dens[9], dens[10], dens[11], dens[12], dens[13], dens[14], dens[15]);

  // Get the max buffer RR RR RR RR RR RR RR RR NR DN is 10 bytes, and 15 deno
  ci->output = (unsigned char *)malloc(MAX_AVAILABLE_COINS * 10 * TOTAL_DENOMINATIONS);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  output_idx = 0;
  individual_sn_output_idx = 0;
  for (i = MIN_DENOMINATION; i <= MAX_DENOMINATION; i++)
  {
    den_idx = i + DENOMINATION_OFFSET;
    if (dens[den_idx] == 0)
    {
      continue;
    }

    den = (int8_t)i;
    debug("Requested denomination %hhx", den);

    done = 0;
    rcnt = scnt = ridx = 0;
    for (j = 0; j < TOTAL_PAGES; j++)
    {
      // NEW: Use improved page management
      page = get_page_by_sn_lock(den, j * RECORDS_PER_PAGE);
      if (page == NULL)
      {
        error("Failed to get page#%d for denomination %02hhx:%d", j, i);
        continue;
      }

      start = end = -1;
      // RESTORED: Complex range detection logic from old code
      // We add +1 to indicated that we finished staff for this page and we need to clean up
      for (k = 0; k < RECORDS_PER_PAGE + 1; k++)
      {
        mfs = page->data[k * 17 + 16];
        if (mfs != 0 || k == RECORDS_PER_PAGE)
        {
          // We just started
          if (start == -1)
            continue;

          tmp_cnt = j * RECORDS_PER_PAGE + k - start;
          // Single page
          if (tmp_cnt == 1)
          {
            debug("Den %hhx, page#%d. SN %d", den, j, start);
            // 4 bytes per SN
            tmp_individual_sns[scnt] = start;
            scnt++;
          }
          else
          { // Range
            debug("Den %hhx, page#%d. SN Range %d:%d", den, j, start, start + tmp_cnt - 1);
            tmp_ranges_sns[ridx * 2] = start;
            tmp_ranges_sns[ridx * 2 + 1] = start + tmp_cnt - 1;
            rcnt += tmp_cnt;
            ridx++;
          }

          start = -1;
          if (rcnt + scnt >= MAX_AVAILABLE_COINS)
          {
            done = 1;
            debug("Search done for denomination %hhx. Free ranges: %d, Free SN in ranges: %d, Free SN single: %d", den, ridx, rcnt, scnt);

            // RESTORED: Exact output format from old code
            // 3 = (DN + NR + NS) + RR * 8 + SN * 4
            ci->output[output_idx] = den;
            ci->output[output_idx + 1] = (char)ridx & 0xff;
            ci->output[output_idx + 2] = (char)scnt & 0xff;

            for (ri = 0; ri < ridx; ri++)
            {
              put_sn(tmp_ranges_sns[ri * 2], ci->output + output_idx + 3 + (ri * 2) * 4);
              put_sn(tmp_ranges_sns[ri * 2 + 1], ci->output + output_idx + 3 + (ri * 2 + 1) * 4);
            }

            for (ri = 0; ri < scnt; ri++)
            {
              put_sn(tmp_individual_sns[ri], ci->output + output_idx + 3 + ridx * 8 + ri * 4);
            }

            output_idx += 3 + ridx * 8 + scnt * 4;
            ci->output_size = output_idx;

            break;
          }

          continue;
        }

        if (start == -1)
        {
          start = j * RECORDS_PER_PAGE + k;
        }
      }

      // NEW: Use improved page unlocking
      unlock_page(page);
      if (done)
        break;

      // Page ended and no free coins found. Check the rest pages
      if (start == -1)
        continue;
    }
  }

  ci->command_status = (char)STATUS_SUCCESS;

  debug("CMD %s Finished", __func__);
}

void cmd_switch_shard_sum_with_sns(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int i, j, k;
  int8_t den;
  int den_idx;
  int coin_length, total_coins, total_new_coins;
  struct page_s *page;
  uint8_t mfs;
  uint32_t si;
  uint8_t shard_id;
  unsigned char xor[16];
  uint32_t sn;
  int sn_idx;
  unsigned char *sm;
  int rv;
  int is_test = 0;
  int passed, failed;
  char input[16];  // RESTORED: Binary input buffer from old code
  char output[16]; // RESTORED: Binary output buffer from old code
  unsigned char pang[16];
  unsigned char *p;
  uint64_t value;
  uint64_t total_v3_value;
  uint64_t total_v3_whole_value;
  uint32_t total_value;

  debug("CMD %s Started", __func__);

  // 16CH + 4SI + SH + ST + 16SM + 2ONR + (ODN + 4OSN)=5atleast + 2NR + (DN+4SN)=5atleast +  +2EOF
  if (ci->body_size < 50)
  {
    error("Invalid command length: %d. Need at least 50", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  si = get_u32(payload);
  debug("Session ID %x", si);
  if (si == 0)
  {
    is_test = 1;
    debug("Test mode");
  }

  shard_id = (uint8_t)payload[4];
  if (shard_id > MAX_SHARD)
  {
    error("Incorrect Shard ID");
    ci->command_status = ERROR_INVALID_SHARD;
    return;
  }

  sm = &payload[6];
  total_coins = (payload[22] << 8) | payload[23];
  coin_length = total_coins * 5;

  p = &payload[24 + coin_length];
  memcpy(pang, p, 16);

  total_new_coins = (p[16] << 8) | p[17];

  debug("Deleting %d legacy coins shard %d, an %02x%02x%02x...%02x istest %d. New coins %d, pang %02x%02x%02x...%02x",
        total_coins, shard_id, sm[0], sm[1], sm[2], sm[15], is_test, total_new_coins, pang[0], pang[1], pang[2], pang[15]);

  // Calculate new coins
  total_v3_value = 0;
  for (i = 0; i < total_new_coins; i++)
  {
    den = ((uint8_t)p[18 + i * 5]);
    sn = get_sn(&p[18 + 1 + i * 5]);
    value = coin_value(den, sn);

    debug("New coin den %hhx, SN %u val %llu", den, sn, value);
    total_v3_value += value;
  }

  total_v3_whole_value = total_v3_value / 100000000;
  debug("Total value %llu", total_v3_value);
  debug("Total whole value %llu", total_v3_whole_value);

  // RESTORED: Exact validation logic from old code
  // We verify AN here in delete
  if (shard_id == SHARD_CLOUDCOIN)
  {
    total_value = legacy_calc_total(&payload[24], total_coins);
    debug("Total value of cc1 cloudcoins %u", total_value);
    if (total_value != total_v3_whole_value || total_value == 0)
    {
      error("Amount mismatch");
      ci->command_status = ERROR_AMOUNT_MISMATCH;
      return;
    }

    if (total_value >= 1000000)
    {
      error("Too many coins to convert");
      ci->command_status = ERROR_TOO_MANY_COINS;
      return;
    }

    if (is_test)
    {
      rv = legacy_detect(&payload[24], total_coins, &passed, &failed, NULL);
      if (rv != STATUS_SUCCESS)
      {
        error("Failed to detect coins from the legacy RAIDA");
        ci->command_status = rv;
        return;
      }
      debug("passed %d, failed %d", passed, failed);
      if (failed > 0 || passed != total_coins)
      {
        error("Some of the coins are counterfeit");
        ci->command_status = ERROR_BAD_COINS;
        return;
      }
    }
    else
    {
      rv = legacy_delete(sm, &payload[24], total_coins);
    }
  }
  else if (shard_id == SHARD_SUPERCOIN)
  {
    total_value = (int)((double)total_coins * 85.125);

    debug("Total of cc2 coins %u", total_value);
    if (total_value != total_v3_whole_value || total_value == 0)
    {
      error("Amount mismatch");
      ci->command_status = ERROR_AMOUNT_MISMATCH;
      return;
    }

    if (is_test)
      rv = cc2_detect(&payload[24], total_coins, &passed, &failed, NULL);
    else
      rv = cc2_delete(sm, &payload[24], total_coins);
  }
  else
  {
    error("Invalid shardID %d", shard_id);
    ci->command_status = ERROR_INVALID_SHARD_ID;
    return;
  }

  if (rv != STATUS_SUCCESS)
  {
    error("Failed to detect coins from the legacy RAIDA");
    ci->command_status = rv;
    return;
  }

  mfs = get_mfs();

  // RESTORED: Exact hash generation logic from old code
  // Updating ANs
  for (i = 0; i < total_new_coins; i++)
  {
    den = ((uint8_t)p[18 + i * 5]);
    sn = get_sn(&p[18 + 1 + i * 5]);

    debug("den %hhx, SN %u", den, sn);

    // NEW: Use improved page management
    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;

    // RESTORED: Exact binary input construction from old code
    memcpy(input, pang, 16);
    input[0] = den;
    put_sn(sn, &input[1]);

    // RESTORED: Direct MD5 hashing (no dual hash complexity)
    md5(input, output);
    debug("AN (test %d) set to %02x%02x%02x...%02x", is_test, output[0], output[1], output[2], output[15]);

    if (is_test)
    {
      debug("Test mode. Not doing anything");
      unlock_page(page);
      continue;
    }

    memcpy(&page->data[sn_idx * 17], output, 16);

    // Set Months From Start
    page->data[sn_idx * 17 + 16] = mfs;
    page->is_dirty = 1;

    // RESTORED: Statistics tracking
    inc_stat(POWN_FIELD_IDX, 1);
    inc_stat(POWN_VALUE_FIELD_IDX, get_den_value(den));

    // NEW: Update bitmap to mark coin as not free
    update_free_pages_bitmap(den, sn, 0);

    unlock_page(page);
  }

  ci->command_status = (char)STATUS_SUCCESS;

  debug("CMD %s Finished", __func__);
}

/*
 * Moves coins from one shard to another.
 * Does this by calling the Delete Coins service on another RAIDA and then creating the coins on itself. A session ID created by the client is given so the client can make another call with the serial numbers it wants to own.
 *
 */
void cmd_switch_shard_sum(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int i, j, k;
  int minden, maxden;
  int8_t den;
  int ri;
  int den_idx;
  int coin_length, total_coins;
  struct page_s *page;
  uint8_t mfs;
  int rcnt, scnt, ridx, tmp_cnt;
  int start, end;
  int output_idx;
  int individual_sn_output_idx;
  uint32_t si;
  uint32_t tmp_individual_sns[MAX_AVAILABLE_COINS];
  uint32_t tmp_ranges_sns[MAX_AVAILABLE_COINS * 2];
  uint8_t done;
  uint8_t shard_id;
  int num_coins_to_alloc, digits;
  uint32_t total_value;
  unsigned char xor[16];
  uint32_t sn;
  int sn_idx;
  unsigned char *an;
  int rv;

  debug("CMD %s Started", __func__);

  // 16CH + 4SI + SH + ST + 16SM + (DN + 4SN) +2EOF
  if (ci->body_size < 45)
  {
    error("Invalid command length: %d. Need at least 45", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  si = get_u32(payload);
  debug("Session ID %x", si);

  coin_length = ci->body_size - 40;
  if (coin_length % 5)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 5;
  shard_id = (uint8_t)payload[4];

  debug("Total %d coins from shard %d", total_coins, shard_id);

  if (shard_id > MAX_SHARD)
  {
    error("Incorrect Shard ID");
    ci->command_status = ERROR_INVALID_SHARD;
    return;
  }

  minden = DEN_1;
  maxden = DEN_100000;

  // We verify AN here in delete
  an = &payload[6];
  if (shard_id == SHARD_CLOUDCOIN)
  {
    total_value = legacy_calc_total(&payload[22], total_coins);

    debug("Total value %u, Deleting %d cloudcoins %d, an %02x%02x%02x...%02x", total_value, total_coins, an[0], an[1], an[2], an[15]);
    if (total_value >= 1000000)
    {
      error("Too many coins to convert");
      ci->command_status = ERROR_TOO_MANY_COINS;
      return;
    }

    rv = legacy_delete(an, &payload[22], total_coins);
  }
  else if (shard_id == SHARD_SUPERCOIN)
  {
    total_value = (int)((double)total_coins * 85.125);

    debug("Total %u deleting %d cc2 coins, an %02x%02x%02x...%02x", total_value, total_coins, an[0], an[1], an[2], an[15]);

    rv = cc2_delete(an, &payload[22], total_coins);
  }
  else
  {
    error("Invalid shardID %d", shard_id);
    ci->command_status = ERROR_INVALID_SHARD_ID;
    return;
  }

  if (rv != STATUS_SUCCESS)
  {
    error("Failed to delete coins from the legacy RAIDA");
    ci->command_status = rv;
    return;
  }

  if (total_value == 0)
  {
    error("No coins");
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  digits = 6;
  if (total_value < 100000)
  {
    maxden = DEN_10000;
    digits--;
    if (total_value < 10000)
    {
      maxden = DEN_1000;
      digits--;
      if (total_value < 1000)
      {
        maxden = DEN_100;
        digits--;
        if (total_value < 100)
        {
          maxden = DEN_10;
          digits--;
          if (total_value < 10)
          {
            maxden = DEN_1;
            digits--;
          }
        }
      }
    }
  }

  // 16 coins per digit (spare coins) (each digit might require up to 9 coins from 0 to 9. e.g. 1280 requires  8 coins of 10x denomination
  num_coins_to_alloc = digits * 10 * MAX_AVAILABLE_COINS;

  debug("Min/Max den %d/%d, digits %d, coins to alloc %d", minden, maxden, digits, num_coins_to_alloc);

  // Get the max buffer RR RR RR RR RR RR RR RR DN NR is 10 bytes
  ci->output = (unsigned char *)malloc(num_coins_to_alloc * 10);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  output_idx = 0;
  individual_sn_output_idx = 0;

  for (i = minden; i <= maxden; i++)
  {
    den_idx = i + DENOMINATION_OFFSET;
    den = (int8_t)i;

    debug("Requested denomination %hhx", den);

    done = 0;
    rcnt = scnt = ridx = 0;
    for (j = 0; j < TOTAL_PAGES; j++)
    {
      // UPDATED: Use new page management function
      page = get_page_by_sn_lock(den, j * RECORDS_PER_PAGE);
      if (page == NULL)
      {
        error("Failed to get page#%d for denomination %02hhx:%d", j, i);
        continue;
      }

      // Check if page is reserved already by someone else
      if (page_is_reserved(page))
      {
        debug("Page %d is reserved, reserved at %lu", j, page->reserved_at);
        unlock_page(page);
        continue;
      }
      // End Check

      // Reserve for a few seconds
      reserve_page(page, si);

      start = end = -1;
      // We add +1 to indicated that we finished staff for this page and we need to clean up
      for (k = 0; k < RECORDS_PER_PAGE + 1; k++)
      {
        mfs = page->data[k * 17 + 16];
        //     debug("den %hhx page%d k=%d %02x %02x %02x mfs=%d", i, j, k, page->data[k * 17], page->data[k * 17 + 1], page->data[k * 17 + 2], page->data[k * 17 + 16]);
        //     mfs != 0 is OK, that is a signal for us to start processing ranges
        if (mfs != 0 || k == RECORDS_PER_PAGE)
        {
          // We just started
          if (start == -1)
            continue;

          tmp_cnt = j * RECORDS_PER_PAGE + k - start;
          // Single page
          if (tmp_cnt == 1)
          {
            debug("Den %hhx, page#%d. SN %d", den, j, start);
            // 4 bytes per SN
            tmp_individual_sns[scnt] = start;
            scnt++;
          }
          else
          { // Range
            debug("Den %hhx, page#%d. SN Range %d:%d", den, j, start, start + tmp_cnt - 1);
            tmp_ranges_sns[ridx * 2] = start;
            tmp_ranges_sns[ridx * 2 + 1] = start + tmp_cnt - 1;
            rcnt += tmp_cnt;
            ridx++;
          }

          start = -1;
          if (rcnt + scnt >= MAX_AVAILABLE_COINS)
          {
            done = 1;
            debug("Search done for denomination %hhx. Free ranges: %d, Free SN in ranges: %d, Free SN single: %d", den, ridx, rcnt, scnt);

            // 3 = (DN + NR + NS) + RR * 8 + SN * 4

            ci->output[output_idx] = den;
            ci->output[output_idx + 1] = (char)ridx & 0xff;
            ci->output[output_idx + 2] = (char)scnt & 0xff;

            for (ri = 0; ri < ridx; ri++)
            {
              put_sn(tmp_ranges_sns[ri * 2], ci->output + output_idx + 3 + (ri * 2) * 4);
              put_sn(tmp_ranges_sns[ri * 2 + 1], ci->output + output_idx + 3 + (ri * 2 + 1) * 4);
            }

            for (ri = 0; ri < scnt; ri++)
            {
              put_sn(tmp_individual_sns[ri], ci->output + output_idx + 3 + ridx * 8 + ri * 4);
            }

            output_idx += 3 + ridx * 8 + scnt * 4;
            ci->output_size = output_idx;

            break;
          }

          continue;
        } // if (mfs != 0 || k == RECORDS_PER_PAGE)

        if (start == -1)
        {
          start = j * RECORDS_PER_PAGE + k;
        }
      } // records in page loop

      unlock_page(page);
      if (done)
        break;

      // Page ended and no free coins found. Check the rest pages
      if (start == -1)
        continue;
    } // page loop
  } // den loop

  ci->command_status = (char)STATUS_SUCCESS;

  debug("CMD %s Finished", __func__);
}

/*
 * Takes ownership of coins that have been moved from another shard.
 */
void cmd_pickup_coins(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  uint32_t si;
  uint32_t sn;
  int coin_length, total_coins;
  int i;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  uint8_t mfs;
  char input[16];  // RESTORED: Binary input buffer from old code
  char output[16]; // RESTORED: Binary output buffer from old code

  debug("CMD %s Started", __func__);

  // 16CH + 4SI + 16AU + (at least one SN + DN) = 5 + 2EOF
  if (ci->body_size < 43)
  {
    error("Invalid command length: %d. Need At least 43", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  mfs = get_mfs();
  si = get_u32(payload);
  debug("Session ID %x", si);

  coin_length = ci->body_size - 38;
  if (coin_length % 5)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 5;
  debug("Requested %d coins to create", total_coins);

  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[20 + i * 5]);
    sn = get_sn(&payload[21 + i * 5]);

    debug("den %hhx, SN %u", den, sn);

    // NEW: Use improved page management
    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    // RESTORED: Session validation from old code
    debug("Page %d reserved_by_sid: %x", page->no, page->reserved_by);
    if (page->reserved_by != si)
    {
      error("Page %u is not reserved by SID supplied: %x", page->no, si);
      ci->command_status = ERROR_PAGE_IS_NOT_RESERVED;
      unlock_page(page);
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;

    // RESTORED: Exact binary input construction from old code
    memcpy(input, &payload[4], 16);
    input[0] = den;
    put_sn(sn, &input[1]);

    // RESTORED: Direct MD5 hashing (no dual hash complexity)
    md5(input, output);
    debug("AN set to %02x%02x%02x...%02x", output[0], output[1], output[2], output[15]);

    memcpy(&page->data[sn_idx * 17], output, 16);

    // Set Months From Start
    page->data[sn_idx * 17 + 16] = mfs;
    page->is_dirty = 1;

    // RESTORED: Statistics tracking
    inc_stat(POWN_FIELD_IDX, 1);
    inc_stat(POWN_VALUE_FIELD_IDX, get_den_value(den));

    // NEW: Update bitmap to mark coin as not free
    update_free_pages_bitmap(den, sn, 0);

    unlock_page(page);
  }

  ci->command_status = (char)STATUS_SUCCESS;

  debug("CMD %s Finished", __func__);
}