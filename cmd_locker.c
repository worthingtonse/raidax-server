/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_locker.c
#   Last Modified : 2025-07-24 11:11
#   Describe      : Locker services, updated for On-Demand Page Cache and Free Pages Bitmap.
#
# ====================================================*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "db.h"
#include "config.h"
#include "utils.h"
#include "locker.h"
#include "stats.h"
#include "crossover.h"

extern struct config_s config;

/*
 * Stores a single locker's worth of coins.
 */
void cmd_store_sum(conn_info_t *ci)
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

  debug("CMD Store Sum");
  mfs = get_mfs();

  if (ci->body_size < 55)
  {
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 50;
  if (coin_length % 5)
  {
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 5;
  debug("Requested %d coins to store in locker", total_coins);

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

  unsigned char *su = &payload[total_coins * 5];
  unsigned char *pn = &payload[total_coins * 5 + 16];

  if (!memcmp(xor, su, 16))
  {
    ci->command_status = (char)STATUS_ALL_PASS;
    if (pn[12] != 0xff || pn[13] != 0xff || pn[14] != 0xff || pn[15] != 0xff)
    {
      error("Invalid PAN. It must end with 0xff 0xff 0xff 0xff");
      ci->command_status = (char)ERROR_INVALID_PAN;
      return;
    }

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
      memcpy(&page->data[sn_idx * 17], pn, 16);
      page->data[sn_idx * 17 + 16] = mfs;
      page->is_dirty = 1;

      // RESTORED: Statistics tracking
      inc_stat(POWN_FIELD_IDX, 1);
      inc_stat(POWN_VALUE_FIELD_IDX, get_den_value(den));

      unlock_page(page);

      // NEW: Update bitmap to mark coin as not free
      update_free_pages_bitmap(den, sn, 0);
    }

    // NEW: Use improved index management with temporary coin array
    coin_t temp_coins[total_coins];
    for (i = 0; i < total_coins; i++)
    {
      temp_coins[i].denomination = ((uint8_t)payload[i * 5]);
      temp_coins[i].sn = get_sn(&payload[i * 5 + 1]);
    }
    locker_index_add_coins(pn, temp_coins, total_coins);
  }
  else
  {
    ci->command_status = (char)STATUS_ALL_FAIL;
  }

  debug("CMD Store Sum finished");
}
/*
 * Removes a set of coins from a specific locker.
 */
void cmd_remove(conn_info_t *ci)
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
  int p, f;
  unsigned char *an, *can;
  struct index_entry *ie;
  int found;
  uint8_t mfs;

  debug("CMD Remove From Locker");

  mfs = get_mfs();

  if (ci->body_size < 55)
  {
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 34;
  if (coin_length % 21)
  {
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 21;
  debug("Requested %d coins to remove from the locker", total_coins);

  an = &payload[0];

  ie = get_coins_from_index(an);
  if (ie == NULL)
  {
    debug("AN is not found in the index");
    ci->command_status = (char)STATUS_ALL_FAIL;
    return;
  }

  debug("Found %d coins", ie->num_coins);

  // Output buffer
  ci->output_size = (total_coins / 8) + 1;
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  // all zeroes (failed coins)
  memset(ci->output, 0, ci->output_size);

  p = f = 0;
  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[i * 21 + 16]);
    sn = get_sn(&payload[i * 21 + 16 + 1]);
    can = &payload[i * 21 + 16 + 5];

    debug("den %hhx, SN %u", den, sn);

    // Check if the requested coin belongs to the index
    found = 0;
    for (j = 0; j < ie->num_coins; j++)
    {
      if (ie->coins[j].denomination == den && ie->coins[j].sn == sn)
      {
        found = 1;
        break;
      }
    }

    if (!found)
    {
      debug("Coin %hhx, SN %u is not found in the index. It won't be deleted", den, sn);
      f++;
      continue;
    }

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    // Update the AN of the coin. This way we are removing it from the locker
    ci->output[i / 8] |= 1 << (i % 8);
    p++;

    debug("Setting AN to %02x%02x%02x ... %02x%02x", can[0], can[1], can[2], can[14], can[15]);
    memcpy(&page->data[sn_idx * 17], can, 16);
    page->data[sn_idx * 17 + 16] = mfs;
    page->is_dirty = 1;

    unlock_page(page);

    // Note: The coin is still in circulation, just with a new AN.
    // The bitmap status does not change (it remains 'not free').
  }

  if (p > 0)
  {
    // NEW: Use improved index management with temporary coin array for removed coins
    coin_t temp_coins[p];
    int temp_idx = 0;

    for (i = 0; i < total_coins; i++)
    {
      den = ((uint8_t)payload[i * 21 + 16]);
      sn = get_sn(&payload[i * 21 + 16 + 1]);

      // Check if this coin was successfully processed
      if (ci->output[i / 8] & (1 << (i % 8)))
      {
        temp_coins[temp_idx].denomination = den;
        temp_coins[temp_idx].sn = sn;
        temp_idx++;
      }
    }

    locker_index_remove_coins(an, temp_coins, p);
  }

  if (p > 0 && f == 0)
    ci->command_status = (char)STATUS_ALL_PASS;
  else if (p == 0 && f > 0)
    ci->command_status = (char)STATUS_ALL_FAIL;
  else
    ci->command_status = (char)STATUS_MIXED;

  debug("CMD Remove from Locker finished");
}

/*
 * Retrieves the denominations and serial numbers of all coins in a locker.
 */
void cmd_peek(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int i;
  struct index_entry *ie;

  debug("CMD Peek");

  if (ci->body_size != 34)
  {
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  ie = get_coins_from_index(payload);
  if (ie == NULL)
  {
    ci->command_status = (char)STATUS_ALL_FAIL;
    return;
  }

  ci->command_status = (char)STATUS_ALL_PASS;
  ci->output_size = ie->num_coins * 5;
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  for (i = 0; i < ie->num_coins; i++)
  {
    ci->output[i * 5] = ie->coins[i].denomination;
    put_sn(ie->coins[i].sn, &ci->output[i * 5 + 1]);
  }

  debug("CMD Peek finished");
}

/*
 * Puts a bundle of coins up for sale as a single tradeable unit.
 */
void cmd_put_for_sale(conn_info_t *ci)
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
  int p, f;
  unsigned char xor[16];
  uint8_t mfs;
  uint8_t f_coin_type;
  uint8_t laste;
  uint32_t price;
  uint8_t address_size;
  unsigned char address[128], *pt;
  char order_path[PATH_MAX];
  int fd, rv;
  struct index_entry *ie;
  uint64_t amount;
  debug("CMD Put For Sale");

  mfs = get_mfs();

  if (ci->body_size < 184)
  {
    error("Invalid command length: %d. Need at least 184", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 179;
  if (coin_length % 5)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 5;
  debug("Requested %d coins to put for sale", total_coins);

  memset(xor, 0, 16);
  amount = 0;
  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[i * 5]);
    sn = get_sn(&payload[i * 5 + 1]);

    // NEW: Use improved page management
    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return; // ✅ FIXED: Removed free(coins_to_add)
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    for (j = 0; j < 16; j++)
    {
      xor[j] ^= page->data[sn_idx * 17 + j];
    }

    amount += coin_value(den, sn);
    unlock_page(page);
  }

  // Compare sum
  debug("xor %02x%02x...%02x payload %02x%02x...%02x", xor[0], xor[1], xor[15],
        payload[total_coins * 5], payload[total_coins * 5 + 1], payload[total_coins * 5 + 15]);
  if (memcmp(xor, &payload[total_coins * 5], 16) != 0)
  {
    debug("One or more of the SNs are counterfeit");
    ci->command_status = (char)STATUS_ALL_FAIL;
    return;
  }

  debug("All SNs are authentic. Setting ANs");
  ci->command_status = (char)STATUS_ALL_PASS;

  pt = &payload[total_coins * 5 + 16];
  f_coin_type = payload[total_coins * 5 + 16 + 13];
  price = get_u32(&payload[total_coins * 5 + 16 + 9]);
  address_size = payload[total_coins * 5 + 32];

  debug("PN is %02X%02X%02X ... %02X%02X%02X%02X type %u, price %u, addrsize %u, amount %llu",
        payload[total_coins * 5 + 16], payload[total_coins * 5 + 16 + 1],
        payload[total_coins * 5 + 16 + 2], payload[total_coins * 5 + 16 + 12],
        payload[total_coins * 5 + 16 + 13], payload[total_coins * 5 + 16 + 14],
        payload[total_coins * 5 + 16 + 15], f_coin_type, price, address_size, amount);

  if (!is_good_trade_coin_type(f_coin_type))
  {
    error("Invalid Coin Type");
    ci->command_status = (char)ERROR_INVALID_TRADE_COIN;
    return;
  }

  // Check if the last bytes are ok
  if (payload[total_coins * 5 + 16 + 14] != 0xee || payload[total_coins * 5 + 16 + 15] != 0xee)
  {
    error("Invalid PAN. It must end with 0xee 0xee");
    ci->command_status = (char)ERROR_INVALID_PAN;
    return;
  }

  if (address_size < 16 || address_size > 120)
  {
    error("Invalid crypto address size");
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  // check if there is no similar locker present
  debug("Checking if no entry exists with the same amount");
  ie = get_entry_from_trade_index(f_coin_type, total_coins, price);
  if (ie != NULL)
  {
    error("Trade locker already exists");
    ci->command_status = (char)ERROR_TRADE_LOCKER_EXISTS;
    return;
  }

  // RESTORED: Critical address storage logic
  memset(address, 0, sizeof(address));
  memcpy(address, &payload[total_coins * 5 + 32 + 1], address_size);

  debug("Saving address in the orderbook");
  sprintf((char *)&order_path, "%s/Trades/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
          config.cwd, pt[0], pt[1], pt[2], pt[3], pt[4], pt[5], pt[6], pt[7],
          pt[8], pt[9], pt[10], pt[11], pt[12], pt[13], pt[14], pt[15]);

  fd = open(order_path, O_CREAT | O_WRONLY, 0640);
  if (fd < 0)
  {
    error("Failed to open file %s: %s", order_path, strerror(errno));
    ci->command_status = ERROR_FILESYSTEM;
    return; // ✅ FIXED: Removed free(coins_to_add)
  }

  rv = write(fd, (unsigned char *)address, address_size);
  if (rv != address_size)
  {
    error("Failed to write to file %s: %s", order_path, strerror(errno));
    ci->command_status = ERROR_FILESYSTEM;
    close(fd);
    return; // ✅ FIXED: Removed free(coins_to_add)
  }
  close(fd);

  // NEW: Update coin data with improved page management
  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[i * 5]);
    sn = get_sn(&payload[i * 5 + 1]);

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Weird. We can't get the same page we got already. coin %d, sn %d -> %hhx",
            i, sn, den);
      ci->command_status = ERROR_INTERNAL;
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    memcpy(&page->data[sn_idx * 17], &payload[total_coins * 5 + 16], 16);
    page->data[sn_idx * 17 + 16] = mfs;
    page->is_dirty = 1;

    // RESTORED: Statistics tracking
    inc_stat(POWN_FIELD_IDX, 1);
    inc_stat(POWN_VALUE_FIELD_IDX, get_den_value(den));

    unlock_page(page);

    // NEW: Update bitmap to mark coin as not free
    update_free_pages_bitmap(den, sn, 0);
  }

  // NEW: Use improved index management but pass coin data directly
  // Create temporary coin array for index function
  coin_t temp_coins[total_coins];
  for (i = 0; i < total_coins; i++)
  {
    temp_coins[i].denomination = ((uint8_t)payload[i * 5]);
    temp_coins[i].sn = get_sn(&payload[i * 5 + 1]);
  }
  trade_locker_index_add_coins(pt, temp_coins, total_coins);

  debug("CMD Put For Sale finished");
}
/*
 * Lists available trade lockers for a given currency type.
 */
void cmd_list_lockers_for_sale(conn_info_t *ci)
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
  int p, f;
  unsigned char xor[16];
  uint8_t mfs;
  uint8_t f_coin_type;
  uint8_t nr;
  uint8_t laste;
  uint16_t price;
  uint8_t address_size;
  unsigned char address[128], *pt;
  char order_path[PATH_MAX];
  int fd, rv;
  struct index_entry **ies, *ie;
  int total_records;
  uint64_t value;

  debug("CMD List lockers For Sale");

  if (ci->body_size != 20)
  {
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  f_coin_type = payload[0];
  nr = payload[1];
  if (!is_good_trade_coin_type(f_coin_type))
  {
    ci->command_status = (char)ERROR_INVALID_TRADE_COIN;
    return;
  }

  debug("List %d records of %d type", nr, f_coin_type);

  ies = (struct index_entry **)malloc(sizeof(struct index_entry *) * nr);
  if (ies == NULL)
  {
    error("Can't alloc buffer for the index entries");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  memset(ies, 0, sizeof(struct index_entry *) * nr);
  total_records = load_coins_from_trade_index(f_coin_type, nr, ies);

  debug("Loaded %d records", total_records);

  ci->command_status = (char)STATUS_ALL_PASS;
  ci->output_size = total_records * 13; // 1coinType + 8TotalCoin + 4Price
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    free(ies);
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  // RESTORED: Complete logic from old code including filesystem check
  for (i = 0; i < total_records; i++)
  {
    ie = ies[i];

    debug("num coins %d, %02x%02x...%02x%02x%02x%02x", ie->num_coins, ie->an[0], ie->an[1], ie->an[12], ie->an[13], ie->an[14], ie->an[15]);
    pt = ie->an;

    // RESTORED: Check if the order file exists in filesystem
    sprintf((char *)&order_path, "%s/Trades/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            config.cwd, pt[0], pt[1], pt[2], pt[3], pt[4], pt[5], pt[6], pt[7],
            pt[8], pt[9], pt[10], pt[11], pt[12], pt[13], pt[14], pt[15]);

    if (access(order_path, F_OK) < 0)
    {
      debug("No transaction recorded for this locker. Ignoring");
      continue;
    }

    value = calc_coins_in_trade_locker(ie);
    debug("Total coins %llu", value);
    value = swap_uint64(value);
    debug("Total coins (swapped) %llu", value);

    // RESTORED: Original 13-byte record format
    ci->output[i * 13] = f_coin_type;
    memcpy(ci->output + (i * 13) + 1, (char *)&value, 8);

    // RESTORED: Price extraction from specific AN bytes (not from &ie->an[9])
    ci->output[i * 13 + 9] = pt[9];
    ci->output[i * 13 + 10] = pt[10];
    ci->output[i * 13 + 11] = pt[11];
    ci->output[i * 13 + 12] = pt[12];
  }

  free(ies);
  debug("CMD List Lockers for Sale done");
}

/*
 * Allows a user to buy a trade locker, transferring ownership.
 */
void cmd_buy(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  uint32_t sn;
  int i, j;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  uint8_t mfs;
  uint8_t f_coin_type;
  unsigned char *pt;
  char order_path[PATH_MAX];
  int fd, rv;
  struct index_entry *ie;
  uint64_t total_coins;
  uint32_t price, bprice;
  coin_t *cc;
  unsigned char txid[32], receipt_id[16];
  int memo_size;
  char memo[256];
  unsigned char *locker_key;
  char *btc_key = NULL;
  int btc_key_size = 0;
  char body[155 + 1500 + 3000]; // 3k is for btc_key
  char *response_body;
  int max_address_size = 62;
  uint8_t status;
  int olength;
  int bkeysize;
  unsigned char address[128];
  int address_size;

  debug("CMD Buy");

  mfs = get_mfs();

  // NEW: Enhanced input validation
  if (ci->body_size < 96)
  {
    error("Invalid command length: %d. Need at least 96", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  locker_key = &payload[0];
  debug("%02x%02x", locker_key[14], locker_key[15]);
  if (locker_key[14] != 0xff && locker_key[15] != 0xff)
  {
    error("Invalid locker key");
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  f_coin_type = payload[16];
  if (!is_good_trade_coin_type(f_coin_type))
  {
    error("Invalid Coin Type");
    ci->command_status = (char)ERROR_INVALID_TRADE_COIN;
    return;
  }

  total_coins = *((uint64_t *)&payload[17]);
  total_coins = swap_uint64(total_coins);

  price = get_u32(&payload[25]);

  debug("coin type %d, total amount value %llu, price %lu, LK %02x%02x...%02x%02x",
        f_coin_type, total_coins, price, locker_key[0], locker_key[1], locker_key[14], locker_key[15]);

  memset(address, 0, 128);
  memcpy(txid, &payload[29], 32);
  memcpy(receipt_id, &payload[29 + 32], 16);

  // 16CH+16LK+1CT+8AM+4PRICE + 32TX + 16RECEIPT + 2EOF
  memo_size = ci->body_size - 16 - 16 - 1 - 8 - 4 - 32 - 16 - 2;
  pt = receipt_id;
  debug("memo_Size %d, tx %02x%02x%02x...%02x%02x%02x, receipt %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        memo_size, txid[0], txid[1], txid[2], txid[29], txid[30], txid[31],
        pt[0], pt[1], pt[2], pt[3], pt[4], pt[5], pt[6], pt[7], pt[8], pt[9], pt[10], pt[11], pt[12], pt[13], pt[14], pt[15]);

  if (memo_size > 254)
  {
    error("Memo is too long");
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  strncpy(memo, &payload[29 + 32 + 16], memo_size);

  pt = txid;
  debug("memo %s", memo);
  debug("tx %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        pt[0], pt[1], pt[2], pt[3], pt[4], pt[5], pt[6], pt[7], pt[8], pt[9], pt[10], pt[11], pt[12], pt[13], pt[14], pt[15],
        pt[16], pt[17], pt[18], pt[19], pt[20], pt[21], pt[22], pt[23], pt[24], pt[25], pt[26], pt[27], pt[28], pt[29], pt[30], pt[31]);

  // NEW: Use improved index lookup
  ie = get_entry_from_trade_index(f_coin_type, total_coins, price);
  if (ie == NULL)
  {
    debug("Trade entry not found for coin type %d, amount %llu and price %lu", f_coin_type, total_coins, price);
    ci->command_status = ERROR_TRADE_LOCKER_NOT_FOUND;
    return;
  }

  debug("Make sure coins are ok. Got %u coins", ie->num_coins);
  // NEW: Use improved page validation
  for (j = 0; j < ie->num_coins; j++)
  {
    cc = &ie->coins[j];
    debug("den %02x, sn %u", cc->denomination, cc->sn);

    page = get_page_by_sn_lock(cc->denomination, cc->sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, cc->sn, cc->denomination);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }
    unlock_page(page);
  }

  //  File system validation
  pt = ie->an;
  sprintf((char *)&order_path, "%s/Trades/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
          config.cwd, pt[0], pt[1], pt[2], pt[3], pt[4], pt[5], pt[6], pt[7], pt[8], pt[9], pt[10], pt[11], pt[12], pt[13], pt[14], pt[15]);
  debug("path %s", order_path);
  fd = open(order_path, O_RDONLY, 0640);
  if (fd < 0)
  {
    error("Failed to open file %s: %s", order_path, strerror(errno));
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  address_size = read(fd, address, sizeof(address));
  if (address_size < 0)
  {
    error("Failed to read file %s: %s", order_path, strerror(errno));
    ci->command_status = ERROR_FILESYSTEM;
    close(fd);
    return;
  }

  address[address_size] = 0;
  debug("Read address %s (%d)", address, address_size);
  close(fd);

  //  Crypto transaction processing
  debug("Sending request to python proxy");
  if (f_coin_type == SALE_TYPE_BTC)
  {
    btc_key = get_crypto_key("BTC", &btc_key_size);
    if (btc_key == NULL)
    {
      error("Failed to get BTC key. Was it uploaded?");
      ci->command_status = ERROR_NO_PRIVATE_KEY;
      return;
    }
  }
  else
  {
    error("Unsupported coin type");
    ci->command_status = ERROR_INVALID_TRADE_COIN;
    return;
  }

  debug("btc key size %d", btc_key_size);
  if (btc_key_size > 3000)
  {
    error("Crypto key part is too big");
    ci->command_status = ERROR_INTERNAL;
    free(btc_key);
    return;
  }

  //  Transaction body construction
  bprice = htonl(price);
  bkeysize = htonl(btc_key_size);
  memset(body, 0, sizeof(body));
  body[0] = f_coin_type;
  memcpy(body + 1, receipt_id, 16);
  memcpy(body + 1 + 16, (char *)&bkeysize, 4);
  memcpy(body + 1 + 16 + 4, btc_key, btc_key_size);

  memcpy(body + 1 + 16 + 4 + btc_key_size, (char *)&bprice, 4);
  body[1 + 16 + 4 + btc_key_size + 4] = (char)address_size;
  memcpy(body + 1 + 16 + 4 + btc_key_size + 4 + 1, address, address_size);
  memcpy(body + 1 + 16 + 4 + btc_key_size + 4 + 1 + address_size, txid, 32);

  //: Critical crypto transaction validation
  response_body = proxy_request(CMD_PROXY_SEND_TRANSACTION, &body[0], 1 + 16 + 4 + btc_key_size + 4 + 1 + address_size + 32, &olength, &status);
  if (response_body == NULL || (status != STATUS_SUCCESS && status != STATUS_WAITING))
  {
    error("Invalid response from proxy. Status %u, body %x", status, response_body);
    if (response_body != NULL)
      free(response_body);
    free(btc_key);
    ci->command_status = status;
    return;
  }

  free(btc_key);

  // CRITICAL: Don't transfer coins until payment is confirmed
  if (status == STATUS_WAITING)
  {
    debug("Our request reached the server. The Proxy is waiting for the others");
    if (response_body != NULL)
      free(response_body);

    ci->command_status = status;
    return; // CRITICAL: Exit here - no coin transfer until payment confirmed!
  }

  debug("Returned length %d", olength);
  debug("Crypto withdrawn from the depository. Crypto sent to the user. Updating lockers");

  // NEW: Only execute coin transfer AFTER crypto payment succeeds
  for (j = 0; j < ie->num_coins; j++)
  {
    cc = &ie->coins[j];
    sn = cc->sn;
    den = cc->denomination;

    debug("Changing den %02x, sn %u", cc->denomination, cc->sn);
    // NEW: Use improved page management
    page = get_page_by_sn_lock(cc->denomination, cc->sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      if (response_body != NULL)
        free(response_body);
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    debug("Setting PAN to %02x%02x%02x...%02x", locker_key[0], locker_key[1], locker_key[2], locker_key[15]);

    memcpy(&page->data[sn_idx * 17], locker_key, 16);
    page->data[sn_idx * 17 + 16] = mfs;
    page->is_dirty = 1;

    unlock_page(page);

    // NEW: Update bitmap to mark coin as not free
    update_free_pages_bitmap(cc->denomination, cc->sn, 0);
  }

  // NEW: Use improved index management
  trade_locker_index_remove_coins(ie->an, ie->coins, ie->num_coins);
  locker_index_add_coins(locker_key, ie->coins, ie->num_coins);

  if (response_body != NULL)
    free(response_body);

  ci->command_status = (char)STATUS_ALL_PASS;
  debug("CMD Buy Done");
}
/*
 * Removes a trade locker from sale.
 */
void cmd_remove_trade_locker(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  struct index_entry *ie = get_coins_from_trade_index(payload);
  if (ie == NULL)
  {
    ci->command_status = (char)STATUS_ALL_FAIL;
    return;
  }

  uint8_t mfs = 0; // Free the coins
  for (int i = 0; i < ie->num_coins; i++)
  {
    struct page_s *page = get_page_by_sn_lock(ie->coins[i].denomination, ie->coins[i].sn);
    if (page)
    {
      int sn_idx = ie->coins[i].sn % RECORDS_PER_PAGE;
      page->data[sn_idx * 17 + 16] = mfs;
      page->is_dirty = 1;
      unlock_page(page);

      // ** NEW: Update bitmap to mark coin as free **
      update_free_pages_bitmap(ie->coins[i].denomination, ie->coins[i].sn, 1);
    }
  }

  trade_locker_index_remove_coins(payload, ie->coins, ie->num_coins);
  ci->command_status = (char)STATUS_ALL_PASS;
  debug("CMD RemoveTradeLocker finished.");
}

/*
 * Peeks into a trade locker.
 */
void cmd_peek_trade_locker(conn_info_t *ci)
{
  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  struct index_entry *ie = get_coins_from_trade_index(payload);
  if (ie == NULL)
  {
    ci->command_status = (char)STATUS_ALL_FAIL;
    return;
  }

  ci->output_size = ie->num_coins * 5;
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  for (int i = 0; i < ie->num_coins; i++)
  {
    ci->output[i * 5] = ie->coins[i].denomination;
    put_sn(ie->coins[i].sn, &ci->output[i * 5 + 1]);
  }

  ci->command_status = (char)STATUS_ALL_PASS;
  debug("CMD PeekTradeLocker finished.");
}

/*
 * Stores multiple lockers in a single request.
 */
void cmd_store_multiple_sum(conn_info_t *ci)
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
  int i, j, k;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  int p, f;
  unsigned char xor[16];
  uint8_t mfs;
  uint8_t nl;
  uint16_t nc;
  int idx;
  unsigned char *sp, *pp;
  int lfailed;
  int ioff;

  debug("CMD StoreMultiple Sum");

  mfs = get_mfs();

  // First check this one
  // 16CH + 1NL + 2EOF
  if (ci->body_size < 19)
  {
    error("Invalid command length: %d", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  nl = (uint8_t)payload[0];
  if (nl == 0)
  {
    error("Locker count is zero");
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  debug("Total lockers requested %d", nl);
  // 16CH + NL * ((at least one 2NC + DN + 4SN ) = 5 + 16SU + 16PN) + 2EOF
  if (ci->body_size < 19 + nl * (2 + 5 + 16 + 16))
  {
    error("Invalid command length: %d", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  // NL is taken into account
  idx = 1;
  // First off, check the length - RESTORED: Complete validation logic
  for (i = 0; i < nl; i++)
  {
    nc = (payload[idx] << 8) | payload[idx + 1];
    debug("Checking locker %d/%d. Number of coins %d (idx %d)", i, nl, nc, idx);

    // 16CH + 2EOF --> 2NC + nc * (DN + 4SN) + 16SU + 16PN
    if (ci->body_size < 16 + 2 + idx + 2 + nc * 5 + 16 + 16)
    {
      error("Invalid command length: %d. i %d, Idx %d", ci->body_size, i, idx);
      ci->command_status = ERROR_INVALID_PACKET_LENGTH;
      return;
    }

    idx += 2 + nc * 5 + 16 + 16;
  }

  ci->output = (unsigned char *)malloc((nl / 8) + 1);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  p = f = 0;
  memset(ci->output, 0, (nl / 8) + 1);

  // RESTORED: Complete nested validation logic
  idx = 1;
  for (i = 0; i < nl; i++)
  {
    nc = (payload[idx] << 8) | payload[idx + 1];
    debug("Processing locker %d/%d. Number of coins %d", i, nl, nc);

    memset(xor, 0, 16);
    lfailed = 0;
    for (j = 0; j < nc; j++)
    {
      den = ((uint8_t)payload[idx + 2 + j * 5]);
      sn = get_sn(&payload[idx + 2 + j * 5 + 1]);

      debug("lk %d d %hhx, sn %d", i, den, sn);
      // NEW: Use improved page management
      page = get_page_by_sn_lock(den, sn);
      // we can't return an error because the upcoming or already passed operations could be fine
      if (page == NULL)
      {
        error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx. Continue with other lockers", j, sn, den);
        lfailed = 1;
        break;
      }

      sn_idx = sn % RECORDS_PER_PAGE;
      for (k = 0; k < 16; k++)
      {
        xor[k] ^= page->data[sn_idx * 17 + k];
      }

      unlock_page(page);
    }

    ioff = 2 + nc * 5 + 16 + 16;
    if (lfailed)
    {
      debug("Page acquiring failed for locker %d", i);
      f++;
      idx += ioff;
      continue;
    }

    sp = &payload[idx + 2 + nc * 5];
    pp = &payload[idx + 2 + nc * 5 + 16];
    debug("cmp %02x%02x%02x...%02x%02x vs %02x%02x%02x...%02x%02x", xor[0], xor[1], xor[2], xor[14], xor[15], sp[0], sp[1], sp[2], sp[14], sp[15]);

    // FIXED: Correct comparison - was using wrong variable in old code
    if (memcmp(xor, sp, 16) != 0)
    {
      debug("Locker %d is counterfeit", i);
      f++;
      idx += ioff;
      continue;
    }

    if (pp[12] != 0xff || pp[13] != 0xff || pp[14] != 0xff || pp[15] != 0xff)
    {
      error("Invalid PAN for locker %d. It must end with 0xff 0xff 0xff 0xff", i);
      f++;
      idx += ioff;
      continue;
    }

    debug("Locker %d is authentic. Setting PAN %02x%02x%02x...%02x%02x", i, pp[0], pp[1], pp[2], pp[14], pp[15]);
    lfailed = 0;

    //  Create temp array for index function (like old code pattern)
    coin_t temp_coins[nc];
    for (j = 0; j < nc; j++)
    {
      temp_coins[j].denomination = ((uint8_t)payload[idx + 2 + j * 5]);
      temp_coins[j].sn = get_sn(&payload[idx + 2 + j * 5 + 1]);
    }

    for (j = 0; j < nc; j++)
    {
      den = ((uint8_t)payload[idx + 2 + j * 5]);
      sn = get_sn(&payload[idx + 2 + j * 5 + 1]);

      // ✅ FIXED: Use direct payload access (like old code)
      page = get_page_by_sn_lock(den, sn);
      if (page == NULL)
      {
        error("Weird. We can't get the same page we got already. locker %d, coin %d, sn %d -> %hhx", i, j, sn, den);
        lfailed = 1;
        break;
      }

      debug("setting lk %d d %hhx, sn %d", i, den, sn);
      // We copy the first 12 bytes only. The last four are 0xFF
      sn_idx = sn % RECORDS_PER_PAGE;
      memcpy(&page->data[sn_idx * 17], pp, 16);
      page->data[sn_idx * 17 + 16] = mfs;
      page->is_dirty = 1;

      // RESTORED: Statistics tracking
      inc_stat(POWN_FIELD_IDX, 1);
      inc_stat(POWN_VALUE_FIELD_IDX, get_den_value(den));

      unlock_page(page);

      // NEW: Update bitmap to mark coin as not free
      update_free_pages_bitmap(den, sn, 0);
    }

    if (lfailed)
    {
      debug("Page acquiring failed during update for locker %d", i);
      f++;
      idx += ioff;
      continue;
    }

    debug("locker %d is authentic and updated", i);
    ci->output[i / 8] |= 1 << (i % 8);
    p++;

    // NEW: Use improved index management
    locker_index_add_coins(pp, temp_coins, nc);

    idx += ioff;
  }

  debug("Lockers authentic/failed %d/%d of %d", p, f, nl);

  if (p == nl)
  {
    ci->command_status = (char)STATUS_ALL_PASS;
  }
  else if (f == nl)
  {
    ci->command_status = (char)STATUS_ALL_FAIL;
  }
  else
  {
    ci->command_status = (char)STATUS_MIXED;
    ci->output_size = (nl / 8);
    if (nl % 8)
    {
      ci->output_size++;
    }
  }

  debug("CMD Store MultipleSum finished");
}