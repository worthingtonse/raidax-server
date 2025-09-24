/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_executive.c
#   Last Modified : 2025-08-20 14:00
#   Describe      : Executive Commands for coin creation and management.
#                 ** CONCURRENCY FIX: Corrected a critical deadlock vulnerability
#                 ** in cmd_create_coins by enforcing a canonical lock order.
#
#
# ====================================================*/

#define _GNU_SOURCE
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "db.h"
#include "config.h"
#include "utils.h"
#include "md5.h"

extern struct config_s config;

// Return no more than this number of coins per denomination
#define MAX_AVAILABLE_COINS 1029

// Helper structure for sorting coin creation requests to prevent deadlocks
typedef struct
{
  int8_t den;
  uint32_t sn;
  uint16_t page_no;
  int original_index; // To map results back to the original request order
} coin_request_t;

// Comparison function for qsort to establish a canonical lock ordering
int compare_coin_requests(const void *a, const void *b)
{
  const coin_request_t *req_a = (const coin_request_t *)a;
  const coin_request_t *req_b = (const coin_request_t *)b;

  // Primary sort key: denomination
  if (req_a->den < req_b->den)
    return -1;
  if (req_a->den > req_b->den)
    return 1;

  // Secondary sort key: page number. This is the resource being locked.
  if (req_a->page_no < req_b->page_no)
    return -1;
  if (req_a->page_no > req_b->page_no)
    return 1;

  // Tertiary sort key: serial number, for stable sorting.
  if (req_a->sn < req_b->sn)
    return -1;
  if (req_a->sn > req_b->sn)
    return 1;

  return 0;
}

/*
 * Gets available SNs from the existing pages
 */
// void cmd_get_available_sns(conn_info_t *ci)
// {
//   unsigned char *payload = get_body_payload(ci);
//   int i, j, k;
//   int8_t den;
//   int ri;
//   int den_idx;
//   struct page_s *page;
//   uint8_t mfs;
//   int rcnt, scnt, ridx, tmp_cnt;
//   int start;
//   int output_idx;
//   uint32_t si;
//   uint32_t tmp_individual_sns[MAX_AVAILABLE_COINS];
//   uint32_t tmp_ranges_sns[MAX_AVAILABLE_COINS * 2];
//   uint8_t done;

//   debug("CMD %s Started", __func__);

//   if (ci->body_size != 54)
//   {
//     error("Invalid command length: %d. Need 54", ci->body_size);
//     ci->command_status = ERROR_INVALID_PACKET_LENGTH;
//     return;
//   }

//   si = get_u32(payload);
//   debug("Session ID %x", si);
//   // Check auth
//   if (memcmp(&payload[4], config.admin_key, 16) != 0)
//   {
//     error("Failed to check auth. Invalid key");
//     ci->command_status = ERROR_ADMIN_AUTH;
//     return;
//   }

//   ci->output = (unsigned char *)malloc(MAX_AVAILABLE_COINS * 10 * TOTAL_DENOMINATIONS);
//   if (ci->output == NULL)
//   {
//     error("Can't alloc buffer for the response");
//     ci->command_status = ERROR_MEMORY_ALLOC;
//     return;
//   }

//   output_idx = 0;
//   for (i = MIN_DENOMINATION; i <= MAX_DENOMINATION; i++)
//   {
//     den_idx = i + DENOMINATION_OFFSET;
//     if (payload[20 + den_idx] == 0)
//     {
//       continue;
//     }

//     den = (int8_t)i;
//     debug("Requested denomination %hhx", den);

//     done = 0;
//     rcnt = scnt = ridx = 0;
//     for (j = 0; j < TOTAL_PAGES; j++)
//     {
//       page = get_page_by_sn_lock(den, j * RECORDS_PER_PAGE);
//       if (page == NULL)
//       {
//         error("Failed to get page#%d for denomination %02hhx:%d", j, i);
//         continue;
//       }

//       if (page_is_reserved(page))
//       {
//         debug("Page %d is reserved, reserved at %lu", j, page->reserved_at);
//         unlock_page(page);
//         continue;
//       }

//       reserve_page(page, si);

//       start = -1;
//       for (k = 0; k < RECORDS_PER_PAGE; k++)
//       {
//         mfs = page->data[k * 17 + 16];

//         if (mfs != 0)
//         {
//           if (start != -1)
//           {
//             tmp_cnt = (j * RECORDS_PER_PAGE + k) - start;
//             if (tmp_cnt == 1)
//             {
//               tmp_individual_sns[scnt++] = start;
//             }
//             else
//             {
//               tmp_ranges_sns[ridx * 2] = start;
//               tmp_ranges_sns[ridx * 2 + 1] = start + tmp_cnt - 1;
//               rcnt += tmp_cnt;
//               ridx++;
//             }
//             start = -1;
//           }
//         }
//         else
//         {
//           if (start == -1)
//           {
//             start = j * RECORDS_PER_PAGE + k;
//           }
//         }

//         if (rcnt + scnt >= MAX_AVAILABLE_COINS)
//         {
//           done = 1;
//           break;
//         }
//       }

//       if (start != -1 && !done)
//       {
//         tmp_cnt = (j * RECORDS_PER_PAGE + RECORDS_PER_PAGE) - start;
//         if (tmp_cnt == 1)
//         {
//           tmp_individual_sns[scnt++] = start;
//         }
//         else
//         {
//           tmp_ranges_sns[ridx * 2] = start;
//           tmp_ranges_sns[ridx * 2 + 1] = start + tmp_cnt - 1;
//           rcnt += tmp_cnt;
//           ridx++;
//         }
//       }

//       unlock_page(page);
//       if (done)
//         break;
//     }

//     if (ridx > 0 || scnt > 0)
//     {
//       debug("Den %hhx. Free ranges: %d, Free SNs: %d", den, ridx, scnt);
//       ci->output[output_idx++] = den;
//       ci->output[output_idx++] = (char)ridx;
//       ci->output[output_idx++] = (char)scnt;

//       for (ri = 0; ri < ridx; ri++)
//       {
//         put_sn(tmp_ranges_sns[ri * 2], &ci->output[output_idx]);
//         output_idx += 4;
//         put_sn(tmp_ranges_sns[ri * 2 + 1], &ci->output[output_idx]);
//         output_idx += 4;
//       }
//       for (ri = 0; ri < scnt; ri++)
//       {
//         put_sn(tmp_individual_sns[ri], &ci->output[output_idx]);
//         output_idx += 4;
//       }
//     }
//   }

//   ci->output_size = output_idx;
//   ci->command_status = (char)STATUS_SUCCESS;
//   debug("CMD %s Finished", __func__);
// }

////new change with bitmap
/*
 * Gets available SNs using bitmap with legacy page reservation compatibility
 */
void cmd_get_available_sns(conn_info_t *ci)
{
  if (ci->body == NULL)
  {
    error(" command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  uint32_t si;
  int i;

  debug("CMD %s Started", __func__);

  if (ci->body_size != 54)
  {
    error("Invalid command length: %d. Need 54", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  si = get_u32(payload);
  debug("Session ID %x", si);

  if (memcmp(&payload[4], config.admin_key, 16) != 0)
  {
    error("Failed to check auth. Invalid key for get_available_sns.");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  ci->output = (unsigned char *)malloc(MAX_AVAILABLE_COINS * 10 * TOTAL_DENOMINATIONS);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  int output_idx = 0;

  for (i = MIN_DENOMINATION; i <= MAX_DENOMINATION; i++)
  {
    int den_idx = i + DENOMINATION_OFFSET;
    if (payload[20 + den_idx] == 0)
    {
      continue;
    }

    int8_t den = (int8_t)i;
    debug("Requested denomination %hhx", den);

    // Step 1: Get a list of free SNs instantly from the bitmap.
    uint32_t candidate_sns[MAX_AVAILABLE_COINS];
    int candidate_count = get_available_sns_from_bitmap(den, candidate_sns, MAX_AVAILABLE_COINS);
    if (candidate_count == 0)
    {
      continue;
    }

    // Step 2: Filter out SNs on reserved pages.
    uint32_t final_sns[MAX_AVAILABLE_COINS];
    int final_count = 0;
    uint16_t last_page_checked = 65535; // Invalid page number

    for (int j = 0; j < candidate_count; j++)
    {
      uint32_t current_sn = candidate_sns[j];
      uint16_t page_no = current_sn / RECORDS_PER_PAGE;

      // Only lock and check each page once
      if (page_no != last_page_checked)
      {
        last_page_checked = page_no;
        struct page_s *page = get_page_by_sn_lock(den, current_sn);
        if (page)
        {
          if (!page_is_reserved(page))
          {
            reserve_page(page, si);
            // All SNs on this unreserved page are valid candidates
            for (int k = j; k < candidate_count && (candidate_sns[k] / RECORDS_PER_PAGE) == page_no; k++)
            {
              final_sns[final_count++] = candidate_sns[k];
            }
          }
          unlock_page(page);
        }
      }
    }

    // Step 3: Reconstruct the original range-finding logic on the final, validated list of SNs.
    if (final_count > 0)
    {
      int rcnt = 0, scnt = 0, ridx = 0;
      uint32_t tmp_individual_sns[MAX_AVAILABLE_COINS];
      uint32_t tmp_ranges_sns[MAX_AVAILABLE_COINS * 2];

      int current_range_start = -1;
      for (int j = 0; j < final_count; j++)
      {
        if (current_range_start == -1)
        {
          current_range_start = final_sns[j];
        }

        // If it's the last SN, or if the next SN is not sequential, end the current range.
        if (j == final_count - 1 || final_sns[j + 1] != final_sns[j] + 1)
        {
          int range_len = final_sns[j] - current_range_start + 1;
          if (range_len == 1)
          {
            tmp_individual_sns[scnt++] = current_range_start;
          }
          else
          {
            tmp_ranges_sns[ridx * 2] = current_range_start;
            tmp_ranges_sns[ridx * 2 + 1] = final_sns[j];
            rcnt += range_len;
            ridx++;
          }
          current_range_start = -1; // Reset for the next potential range
        }
      }

      // Step 4: Format the output buffer exactly like the original function.
      debug("Den %hhx. Free ranges: %d, Free SNs: %d", den, ridx, scnt);
      ci->output[output_idx++] = den;
      ci->output[output_idx++] = (char)ridx;
      ci->output[output_idx++] = (char)scnt;

      for (int ri = 0; ri < ridx; ri++)
      {
        put_sn(tmp_ranges_sns[ri * 2], &ci->output[output_idx]);
        output_idx += 4;
        put_sn(tmp_ranges_sns[ri * 2 + 1], &ci->output[output_idx]);
        output_idx += 4;
      }
      for (int ri = 0; ri < scnt; ri++)
      {
        put_sn(tmp_individual_sns[ri], &ci->output[output_idx]);
        output_idx += 4;
      }
    }
  }

  ci->output_size = output_idx;
  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD %s Finished", __func__);
}

/*
 * Creates coins. The sessionID from the GetAvailableSNs call must be used
 * by the client. Uses  MD5 approach for consistent administrative coin creation.
 */
void cmd_create_coins(conn_info_t *ci)
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
  int i, j;
  int8_t den;
  int sn_idx;
  struct page_s **locked_pages = NULL;
  int num_locked_pages = 0;
  uint8_t mfs;
  unsigned char md_input[64], md_output[64], tmp[16];
  coin_request_t *requests = NULL;

  debug("CMD %s Started", __func__);

  if (ci->body_size < 43)
  {
    error("Invalid command length: %d. Need At least 43", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  mfs = get_mfs();
  si = get_u32(payload);
  debug("Session ID %x", si);

  // Check auth - same logic as legacy
  if (memcmp(&payload[4], config.admin_key, 16) != 0)
  {
    error("Failed to check auth. Invalid key");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  coin_length = ci->body_size - 38;
  if (coin_length % 5)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    goto cleanup_and_exit;
  }

  total_coins = coin_length / 5;
  debug("Requested %d coins to create", total_coins);

  // Concurrency-safe memory allocation
  requests = calloc(total_coins, sizeof(coin_request_t));
  if (!requests)
  {
    error("Failed to allocate memory for request sorting");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  locked_pages = calloc(total_coins, sizeof(struct page_s *));
  if (!locked_pages)
  {
    error("Failed to allocate memory for page tracking");
    ci->command_status = ERROR_MEMORY_ALLOC;
    free(requests);
    return;
  }

  ci->output_size = 16 * total_coins;
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    goto cleanup_and_exit;
  }

  // PHASE 1 - Parse and Sort for Deadlock Prevention
  for (i = 0; i < total_coins; i++)
  {
    requests[i].den = (int8_t)payload[20 + i * 5];
    requests[i].sn = get_sn(&payload[21 + i * 5]);
    requests[i].page_no = requests[i].sn / RECORDS_PER_PAGE;
    requests[i].original_index = i;
  }
  qsort(requests, total_coins, sizeof(coin_request_t), compare_coin_requests);

  // PHASE 2 - Lock All Pages in Canonical Order
  for (i = 0; i < total_coins; i++)
  {
    den = requests[i].den;
    sn = requests[i].sn;

    // Skip if already locked
    int found_existing = 0;
    for (j = 0; j < num_locked_pages; j++)
    {
      if (locked_pages[j]->denomination == den &&
          locked_pages[j]->no == (sn / RECORDS_PER_PAGE))
      {
        found_existing = 1;
        break;
      }
    }

    if (!found_existing)
    {
      struct page_s *page = get_page_by_sn_lock(den, sn);
      if (page == NULL)
      {
        error("Invalid sn or denomination passed for coin, sn %d -> %hhx", sn, den);
        ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
        goto cleanup_and_exit;
      }

      // Session validation - same as legacy
      debug("Page %d reserved_by_sid: %x", page->no, page->reserved_by);
      if (page->reserved_by != si && si != 0xeeeeeeee)
      {
        error("Page %u is not reserved by SID supplied: %x", page->no, si);
        ci->command_status = ERROR_PAGE_IS_NOT_RESERVED;
        unlock_page(page);
        goto cleanup_and_exit;
      }

      locked_pages[num_locked_pages++] = page;
    }
  }

  // PHASE 3 - Process All Coins with Legacy Hash Approach (No Encryption Type Mixing)
  for (i = 0; i < total_coins; i++)
  {
    den = requests[i].den;
    sn = requests[i].sn;
    int original_index = requests[i].original_index;

    // Find locked page
    struct page_s *page = NULL;
    for (j = 0; j < num_locked_pages; j++)
    {
      if (locked_pages[j]->denomination == den &&
          locked_pages[j]->no == (sn / RECORDS_PER_PAGE))
      {
        page = locked_pages[j];
        break;
      }
    }

    if (!page)
    {
      error("Internal error: couldn't find locked page for coin %d", i);
      ci->command_status = ERROR_INTERNAL;
      goto cleanup_and_exit;
    }

    debug("den %hhx, SN %u", den, sn);

    // LEGACY APPROACH: Pure Administrative Hash Generation (No Encryption Type Concerns)
    memset(md_input, 0, sizeof(md_input));
    memset(md_output, 0, sizeof(md_output));
    memset(tmp, 0, sizeof(tmp));

    sprintf(md_input, "%d", config.raida_no);
    sprintf(tmp, "%u", sn);
    strcat(md_input, tmp);

    // Use admin key from payload[16 + 4 + j] = payload[20 + j] as per legacy
    for (j = 0; j < 16; j++)
    {
      sprintf(tmp, "%02x", payload[16 + 4 + j]);
      strcat(md_input, tmp);
    }

    debug("mdinput %s\n", md_input);

    // ALWAYS use MD5 for administrative coin creation (deterministic, encryption-independent)
    md5ilen(md_input, md_output, strlen(md_input));
    debug("done %02x%02x...%02x%02x", md_output[0], md_output[1], md_output[14], md_output[15]);

    sn_idx = sn % RECORDS_PER_PAGE;

    // Return old AN in original order, set new AN
    memcpy(ci->output + original_index * 16, &page->data[sn_idx * 17], 16);
    memcpy(&page->data[sn_idx * 17], md_output, 16);

    // Set Months From Start
    page->data[sn_idx * 17 + 16] = mfs;
    page->is_dirty = 1;

    // Update bitmap if available (optional for compatibility)
    update_free_pages_bitmap(den, sn, 0);
  }

  ci->command_status = (char)STATUS_SUCCESS;

cleanup_and_exit:
  // PHASE 4 - Guaranteed Cleanup
  for (i = 0; i < num_locked_pages; i++)
  {
    if (locked_pages[i])
    {
      unlock_page(locked_pages[i]);
    }
  }

  if (requests)
  {
    free(requests);
  }
  if (locked_pages)
  {
    free(locked_pages);
  }

  if (ci->command_status != STATUS_SUCCESS && ci->output)
  {
    free(ci->output);
    ci->output = NULL;
    ci->output_size = 0;
  }

  debug("CMD %s Finished", __func__);
}

/*
 * Frees coins, making them available again.
 */
void cmd_free_coins(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  uint32_t sn;
  int coin_length, total_coins;
  int i;
  int8_t den;
  int sn_idx;
  struct page_s *page;

  debug("CMD %s Started", __func__);

  if (ci->body_size < 43)
  {
    error("Invalid command length: %d. Need At least 43", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  if (memcmp(&payload[4], config.admin_key, 16) != 0)
  {
    debug("Admin key is not set. Checking RAIDA key");
    error("Failed to check auth. Invalid key");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  coin_length = ci->body_size - 38;
  if (coin_length % 5)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 5;
  debug("Requested %d coins to free", total_coins);

  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[20 + i * 5]);
    sn = get_sn(&payload[21 + i * 5]);

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      // Fail silently or log? For robustness, we'll log and continue.
      error("Could not lock page for den %d, sn %u to free coin.", den, sn);
      continue;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    page->data[sn_idx * 17 + 16] = 0; // Set MFS to zero to free the coin
    page->is_dirty = 1;
    unlock_page(page);

    update_free_pages_bitmap(den, sn, 1);
  }

  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD %s Finished", __func__);
}

/*
 * Deletes coins by verifying their AN and then freeing them.
 */
void cmd_delete_coins(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  uint32_t sn;
  int coin_length, total_coins;
  int i;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  int p, f;

  debug("CMD %s Started", __func__);

  if (ci->body_size < 55)
  {
    error("Invalid command length: %d. Need At least 55", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  if (memcmp(&payload[0], config.admin_key, 16) != 0)
  {
    error("Failed to check auth. Invalid key");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  coin_length = ci->body_size - 34;
  if (coin_length % 21)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 21;
  debug("Requested %d coins to delete", total_coins);

  ci->output = (unsigned char *)malloc((total_coins / 8) + 1);
  if (ci->output == NULL)
  {
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }
  memset(ci->output, 0, (total_coins / 8) + 1);

  p = f = 0;
  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[16 + i * 21]);
    sn = get_sn(&payload[16 + i * 21 + 1]);
    unsigned char *an_to_check = &payload[16 + i * 21 + 5];

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      f++;
      continue;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    if (!memcmp(&page->data[sn_idx * 17], an_to_check, 16))
    {
      ci->output[i / 8] |= 1 << (i % 8);
      p++;
      page->data[sn_idx * 17 + 16] = 0;
      page->is_dirty = 1;
      update_free_pages_bitmap(den, sn, 1);
    }
    else
    {
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

  debug("CMD %s Finished", __func__);
}

/*
 * Gets all SNs from the existing pages for a given denomination
 */
void cmd_get_all_sns(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int j, k;
  int8_t rqden;
  uint8_t mfs;
  size_t size;
  char page_path[PATH_MAX];
  unsigned char page_data[RECORDS_PER_PAGE * 17];
  int fd;

  debug("CMD %s Started", __func__);

  if (ci->body_size != 35)
  {
    error("Invalid command length: %d. Need 35", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }
  if (memcmp(&payload[0], config.admin_key, 16) != 0)
  {
    error("Failed to check auth. Invalid key");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  rqden = payload[16];
  if (rqden < MIN_DENOMINATION || rqden > MAX_DENOMINATION)
  {
    error("Invalid denomination requested.");
    ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
    return;
  }

  size = TOTAL_PAGES * RECORDS_PER_PAGE / 8;
  ci->output = (unsigned char *)malloc(size + 5);
  if (ci->output == NULL)
  {
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }
  memset(ci->output, 0, size + 5);

  ci->output[0] = rqden;
  put_u32(size, &ci->output[1]);

  unsigned char *bitmap = &ci->output[5];

  for (j = 0; j < TOTAL_PAGES; j++)
  {
    uint8_t page_msb = (j >> 8) & 0xff;
    snprintf(page_path, sizeof(page_path), "%s/Data/%02hhx/%02x/%04x.bin", config.cwd, (uint8_t)rqden, page_msb, j);

    fd = open(page_path, O_RDONLY);
    if (fd < 0)
      continue;

    if (read(fd, page_data, sizeof(page_data)) != sizeof(page_data))
    {
      close(fd);
      continue;
    }
    close(fd);

    for (k = 0; k < RECORDS_PER_PAGE; k++)
    {
      mfs = page_data[k * 17 + 16];
      if (mfs != 0)
      {
        int sn_abs = j * RECORDS_PER_PAGE + k;
        int byte_idx = sn_abs / 8;
        int bit_idx = sn_abs % 8;
        if (byte_idx < size)
        {
          bitmap[byte_idx] |= (1 << bit_idx);
        }
      }
    }
  }

  ci->output_size = size + 5;
  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD %s Finished", __func__);
}