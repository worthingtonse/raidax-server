/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_change.c
#   Last Modified : 2025-07-24-11:07
#   Describe      : Change-making command handlers, updated for dual hashing and in-memory bitmap.
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
#include "ht.h"
#include "config.h"
#include "utils.h"

extern struct config_s config;

#define MAX_CHANGE_COINS 64

#define OP_BREAK 0x1
#define OP_JOIN 0x2

/*
 * ** RE-ARCHITECTED **
 * Gets available Change SNs instantly from the in-memory bitmap.
 * This eliminates the slow disk-scanning "mega I/O read problem".
 */
void cmd_get_available_change_sns(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int8_t den;
  int scnt;
  uint32_t si;
  int op;
  uint32_t available_sns[MAX_CHANGE_COINS];

  debug("CMD %s Started", __func__);

  // Validate request size
  if (ci->body_size != 24)
  {
    error("Invalid command length: %d. Need 24", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  si = get_u32(payload);
  op = (int)payload[4];
  if (op != OP_BREAK && op != OP_JOIN)
  {
    error("Invalid operation for get_available_change_sns: %d", op);
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  den = payload[5];
  if (den < MIN_DENOMINATION || den > MAX_DENOMINATION)
  {
    error("Invalid sn or denomination passed %hhx", den);
    ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
    return;
  }

  debug("Session ID %x, den %hhx", si, den);

  // Determine target denomination for the search
  if (op == OP_BREAK)
  {
    debug("Searching for smaller coins for Break operation");
    den--;
  }
  else
  {
    debug("Searching for larger coins for Join operation");
    den++;
  }

  if (den < MIN_DENOMINATION || den > MAX_DENOMINATION)
  {
    error("Target denomination %hhx is out of bounds", den);
    ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
    return;
  }

  // Get available serial numbers from the high-speed in-memory bitmap
  scnt = get_available_sns_from_bitmap(den, available_sns, MAX_CHANGE_COINS);

  ci->output_size = 1 + scnt * 4;
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  ci->output[0] = den;
  for (int i = 0; i < scnt; i++)
  {
    put_sn(available_sns[i], &ci->output[1 + i * 4]);
  }

  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD %s Finished, found %d available SNs from bitmap", __func__, scnt);
}

/*
 * Breaks a single, larger denomination coin into 10 smaller ones.
 */
void cmd_break(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  uint32_t si;
  uint32_t bsn, sn;
  unsigned char *ban, *pan;
  int i;
  int8_t bden, den;
  int sn_idx, bsn_idx;
  struct page_s *dpage, *page;
  uint8_t mfs;
  char input[16];
  int rr;

  debug("CMD %s Started", __func__);

  if (ci->body_size != 253)
  {
    error("Invalid command length: %d. Need 253", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  mfs = get_mfs();
  si = get_u32(payload);

  bden = (int8_t)payload[4];
  bsn = get_u32(&payload[5]);
  ban = (unsigned char *)&payload[9];

  debug("Session ID %x, Coin to break: den %hhx, sn %u", si, bden, bsn);
  if (bden <= MIN_DENOMINATION || bden > MAX_DENOMINATION)
  {
    error("Invalid denomination passed %hhx", bden);
    ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
    return;
  }

  if (check_add_ipht(ci->ip) < 0)
  {
    error("Rate limit exceeded");
    ci->command_status = (char)ERROR_REQUEST_RATE;
    return;
  }

  // Verify the authenticity of the coin being broken
  dpage = get_page_by_sn_lock(bden, bsn);
  if (dpage == NULL)
  {
    error("Invalid sn or denomination passed sn %d -> %hhx", sn, den);
    ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
    return;
  }

  bsn_idx = bsn % RECORDS_PER_PAGE;
  if (memcmp(ban, &dpage->data[bsn_idx * 17], 16) != 0)
  {
    error("Invalid AN for the coin to be broken");
    ci->command_status = STATUS_ALL_FAIL;
    unlock_page(dpage);
    return;
  }
  unlock_page(dpage);

  // Take ownership of the 10 smaller coins
  for (i = 0; i < 10; i++)
  {
    den = ((uint8_t)payload[25 + i * 21]);
    sn = get_sn(&payload[25 + 1 + i * 21]);
    pan = (unsigned char *)&payload[25 + 1 + 4 + i * 21];

    if (den != bden - 1)
    {
      error("Invalid denomination for smaller coin %d. Expected %hhx, got %hhx", i, (bden - 1), den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    if (page->reserved_by != si)
    {
      error("Page %u is not reserved by SID supplied: %x", page->no, si);
      ci->command_status = ERROR_PAGE_IS_NOT_RESERVED;
      unlock_page(page);
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    memcpy(&page->data[sn_idx * 17], pan, 16);
    page->data[sn_idx * 17 + 16] = mfs;
    page->is_dirty = 1;
    unlock_page(page);

    // ** NEW: Update bitmap for the newly created smaller coin **
    update_free_pages_bitmap(den, sn, 0); // Mark as not free
  }

  // "Destroy" the original large coin by giving it a new, secure random AN
  dpage = get_page_by_sn_lock(bden, bsn);
  if (dpage == NULL)
  {
    ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
    return;
  }
  bsn_idx = bsn % RECORDS_PER_PAGE;

  srand(time(NULL) + config.raida_no * 19456);
  rr = rand();
  sprintf(input, "%04x%04x", rr, rr);

  memcpy(&dpage->data[bsn_idx * 17], input, 16);
  dpage->data[bsn_idx * 17 + 16] = 0; // Free the coin
  dpage->is_dirty = 1;
  unlock_page(dpage);

  // ** NEW: Update bitmap for the destroyed larger coin **
  update_free_pages_bitmap(bden, bsn, 1); // Mark as free

  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD %s Finished", __func__);
}

/*
 * Joins 10 smaller denomination coins into a single larger one.
 */
void cmd_join(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  uint32_t si;
  uint32_t bsn, sn;
  unsigned char *ban, *pan;
  int i;
  int8_t bden, den;
  int sn_idx, bsn_idx;
  struct page_s *dpage, *page;
  uint8_t mfs;

  debug("CMD %s Started", __func__);

  if (ci->body_size != 253)
  {
    error("Invalid command length: %d. Need 253", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  mfs = get_mfs();
  si = get_u32(payload);

  // The new, larger coin to be created
  bden = (int8_t)payload[4];
  bsn = get_u32(&payload[5]);
  ban = (unsigned char *)&payload[9]; // The proposed new AN

  debug("Session ID %x, Coin to join into: den %hhx, sn %u", si, bden, bsn);
  if (bden < MIN_DENOMINATION || bden > MAX_DENOMINATION)
  {
    error("Invalid denomination passed %hhx", bden);
    ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
    return;
  }

  // Verify the target page is reserved by the client
  dpage = get_page_by_sn_lock(bden, bsn);
  if (dpage == NULL)
  {
    ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
    return;
  }
  if (dpage->reserved_by != si)
  {
    error("Page %u is not reserved by SID supplied: %x", dpage->no, si);
    ci->command_status = ERROR_PAGE_IS_NOT_RESERVED;
    unlock_page(dpage);
    return;
  }
  unlock_page(dpage);

  // First, verify all 10 smaller coins are authentic
  for (i = 0; i < 10; i++)
  {
    den = ((uint8_t)payload[25 + i * 21]);
    sn = get_sn(&payload[25 + 1 + i * 21]);
    pan = (unsigned char *)&payload[25 + 1 + 4 + i * 21];

    if (den != bden - 1)
    {
      error("Invalid denomination for smaller coin %d. Expected %hhx, got %hhx", i, (bden - 1), den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    if (memcmp(pan, &page->data[sn_idx * 17], 16) != 0)
    {
      error("Invalid AN for smaller coin %d (sn: %u)", i, sn);
      ci->command_status = STATUS_ALL_FAIL;
      unlock_page(page);
      return;
    }
    unlock_page(page);
  }

  // If all are authentic, "destroy" the 10 smaller coins by freeing them
  for (i = 0; i < 10; i++)
  {
    den = ((uint8_t)payload[25 + i * 21]);
    sn = get_sn(&payload[25 + 1 + i * 21]);

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
      continue;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    page->data[sn_idx * 17 + 16] = 0; // Free the coin
    page->is_dirty = 1;
    unlock_page(page);

    // **  Update bitmap for the destroyed smaller coin **
    update_free_pages_bitmap(den, sn, 1); // Mark as free
  }

  // Finally, create the new, larger coin
  dpage = get_page_by_sn_lock(bden, bsn);
  if (dpage == NULL)
  {
    error("Invalid sn or denomination passed sn %d -> %hhx", sn, den);
    ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
    return;
  }

  bsn_idx = bsn % RECORDS_PER_PAGE;
  memcpy(&dpage->data[bsn_idx * 17], ban, 16);
  dpage->data[bsn_idx * 17 + 16] = 0;
  dpage->is_dirty = 1;
  unlock_page(dpage);

  // ** NEW: Update bitmap for the newly created larger coin **
  update_free_pages_bitmap(bden, bsn, 0); // Mark as not free

  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD %s Finished", __func__);
}