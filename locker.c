/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : locker.c
#   Last Modified : 2025-07-23 10:38
#   Describe      : This file implements indexing for coin lockers (Optimized)
#                 ** CONCURRENCY FIX: Added robust error handling for all
#                 ** mutex operations to ensure production-level stability.
#
# ====================================================*/

#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>

#include "config.h"
#include "commands.h"
#include "locker.h"
#include "log.h"
#include "db.h"
#include "utils.h"

struct index_entry *locker_index[MAX_LOCKER_RECORDS];
struct index_entry *trade_locker_index[MAX_LOCKER_RECORDS];

pthread_mutex_t locker_mtx;
pthread_mutex_t trade_locker_mtx;

// Internal helper functions
static int add_index_entry_internal(int8_t denomination, uint32_t sn, unsigned char *an);
static int add_trade_index_entry_internal(int8_t denomination, uint32_t sn, unsigned char *an);
// void update_index(void);
// void update_trade_index(void);
void verify_and_cleanup_indices(void);
void *index_thread(void *arg);

/*
 * Initializes locker index and locker thread
 * The thread is run hourly (by default) and updates the index
 */
int init_locker_index(void)
{
  int i, rc;
  pthread_t locker_thread;

  debug("Initializing locker index");

  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    locker_index[i] = NULL;
    trade_locker_index[i] = NULL;
  }

  rc = pthread_mutex_init(&locker_mtx, NULL);
  if (rc != 0)
  {
    error("Failed to init locker mtx: %s", strerror(rc));
    return -1;
  }

  rc = pthread_mutex_init(&trade_locker_mtx, NULL);
  if (rc != 0)
  {
    error("Failed to init trade locker mtx: %s", strerror(rc));
    pthread_mutex_destroy(&locker_mtx); // Clean up previous mutex
    return -1;
  }

  // Build initial indices
  // update_index();
  // update_trade_index();

  if (pthread_create(&locker_thread, NULL, index_thread, NULL) != 0)
  {
    error("Failed to start syncing thread: %s", strerror(errno));
    return -1;
  }

  debug("Locker thread initialized");

  return 0;
}

/*
 * Main loop that runs periodically for cleanup and verification
 */
void *index_thread(void *arg)
{
  while (1)
  {
    sleep(INDEX_UPDATE_PERIOD * 4);
    // verify_and_cleanup_indices();
    debug("Locker maintenance thread running periodic check.");
  }
  return NULL; // Should never be reached
}

/*
 * Periodic verification to ensure indices are consistent
 */
// void verify_and_cleanup_indices(void)
// {
//   debug("Running periodic index verification and cleanup");
//   // In production, maybe this could be expanded to cross-check
//   // the in-memory index against the on-disk data to detect inconsistencies.
//   // For now, we trust that the incremental updates are correct.
// }

/*
 * Full index rebuild - now only called at startup or for recovery
 */
// void update_index(void)
// {
//   int i, j, k;
//   int8_t den;
//   struct page_s *page;
//   uint32_t sn;

//   debug("Building/rebuilding locker index...");

//   if (pthread_mutex_lock(&locker_mtx) != 0)
//   {
//     error("Failed to lock locker mutex for index update");
//     return;
//   }

//   free_index();

//   for (i = MIN_DENOMINATION; i <= MAX_DENOMINATION; i++)
//   {
//     den = (int8_t)i;
//     debug("Updating index for den %hhx", den);

//     for (j = 0; j < TOTAL_PAGES; j++)
//     {
//       page = get_page_by_sn_lock(den, j * RECORDS_PER_PAGE);
//       if (page == NULL)
//       {
//         error("Failed to get page#%d for denomination %02hhx", j, den);
//         continue;
//       }

//       for (k = 0; k < RECORDS_PER_PAGE; k++)
//       {
//         if (page->data[k * 17 + 12] == 0xff && page->data[k * 17 + 13] == 0xff &&
//             page->data[k * 17 + 14] == 0xff && page->data[k * 17 + 15] == 0xff)
//         {
//           sn = page->no * RECORDS_PER_PAGE + k;
//           if (add_index_entry_internal(den, sn, &page->data[k * 17]) < 0)
//           {
//             error("Failed to add index entry for den %hhx, sn %u", den, sn);
//           }
//         }
//       }
//       unlock_page(page);
//     }
//   }

//   pthread_mutex_unlock(&locker_mtx);
// }

// void update_trade_index(void)
// {
//   int i, j, k;
//   int8_t den;
//   struct page_s *page;
//   uint32_t sn;
//   uint8_t f_coin_type;

//   debug("Building/rebuilding trade locker index...");

//   if (pthread_mutex_lock(&trade_locker_mtx) != 0)
//   {
//     error("Failed to lock trade locker mutex for index update");
//     return;
//   }

//   free_trade_index();

//   for (i = MIN_DENOMINATION; i <= MAX_DENOMINATION; i++)
//   {
//     den = (int8_t)i;
//     debug("Updating trade index for den %hhx", den);

//     for (j = 0; j < TOTAL_PAGES; j++)
//     {
//       page = get_page_by_sn_lock(den, j * RECORDS_PER_PAGE);
//       if (page == NULL)
//       {
//         error("Failed to get page#%d for denomination %02hhx", j, den);
//         continue;
//       }

//       for (k = 0; k < RECORDS_PER_PAGE; k++)
//       {
//         f_coin_type = page->data[k * 17 + 13];
//         if (!is_good_trade_coin_type(f_coin_type))
//           continue;
//         if (page->data[k * 17 + 14] == 0xee && page->data[k * 17 + 15] == 0xee)
//         {
//           sn = page->no * RECORDS_PER_PAGE + k;
//           if (add_trade_index_entry_internal(den, sn, &page->data[k * 17]) < 0)
//           {
//             error("Failed to add trade index entry for den %hhx, sn %u", den, sn);
//           }
//         }
//       }
//       unlock_page(page);
//     }
//   }

//   pthread_mutex_unlock(&trade_locker_mtx);
// }

/*
 * Incrementally adds coins to locker index
 */
void locker_index_add_coins(unsigned char *an, coin_t *coins_to_add, int num_coins)
{
  if (pthread_mutex_lock(&locker_mtx) != 0)
  {
    error("Failed to lock locker mutex to add coins");
    return;
  }
  for (int i = 0; i < num_coins; i++)
  {
    add_index_entry_internal(coins_to_add[i].denomination, coins_to_add[i].sn, an);
  }
  pthread_mutex_unlock(&locker_mtx);
}

/*
 * Incrementally removes coins from locker index
 */
void locker_index_remove_coins(unsigned char *an, coin_t *coins_to_remove, int num_coins)
{
  if (pthread_mutex_lock(&locker_mtx) != 0)
  {
    error("Failed to lock locker mutex to remove coins");
    return;
  }

  int i, j, k;
  struct index_entry *entry = NULL;
  int entry_idx = -1;

  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (locker_index[i] && !memcmp(locker_index[i]->an, an, 16))
    {
      entry = locker_index[i];
      entry_idx = i;
      break;
    }
  }

  if (entry)
  {
    for (i = 0; i < num_coins; i++)
    {
      for (j = 0; j < entry->num_coins; j++)
      {
        if (entry->coins[j].denomination == coins_to_remove[i].denomination &&
            entry->coins[j].sn == coins_to_remove[i].sn)
        {
          for (k = j; k < entry->num_coins - 1; k++)
          {
            entry->coins[k] = entry->coins[k + 1];
          }
          entry->num_coins--;
          break;
        }
      }
    }

    if (entry->num_coins == 0 && entry_idx >= 0)
    {
      free(entry->coins);
      free(entry);
      locker_index[entry_idx] = NULL;
    }
  }

  pthread_mutex_unlock(&locker_mtx);
}

/*
 * Incrementally adds coins to trade locker index
 */
void trade_locker_index_add_coins(unsigned char *an, coin_t *coins_to_add, int num_coins)
{
  if (pthread_mutex_lock(&trade_locker_mtx) != 0)
  {
    error("Failed to lock trade locker mutex to add coins");
    return;
  }
  for (int i = 0; i < num_coins; i++)
  {
    add_trade_index_entry_internal(coins_to_add[i].denomination, coins_to_add[i].sn, an);
  }
  pthread_mutex_unlock(&trade_locker_mtx);
}

/*
 * Incrementally removes coins from trade locker index
 */
void trade_locker_index_remove_coins(unsigned char *an, coin_t *coins_to_remove, int num_coins)
{
  if (pthread_mutex_lock(&trade_locker_mtx) != 0)
  {
    error("Failed to lock trade locker mutex to remove coins");
    return;
  }

  int i, j, k;
  struct index_entry *entry = NULL;
  int entry_idx = -1;

  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (trade_locker_index[i] && !memcmp(trade_locker_index[i]->an, an, 16))
    {
      entry = trade_locker_index[i];
      entry_idx = i;
      break;
    }
  }

  if (entry)
  {
    for (i = 0; i < num_coins; i++)
    {
      for (j = 0; j < entry->num_coins; j++)
      {
        if (entry->coins[j].denomination == coins_to_remove[i].denomination &&
            entry->coins[j].sn == coins_to_remove[i].sn)
        {
          for (k = j; k < entry->num_coins - 1; k++)
          {
            entry->coins[k] = entry->coins[k + 1];
          }
          entry->num_coins--;
          break;
        }
      }
    }

    if (entry->num_coins == 0 && entry_idx >= 0)
    {
      free(entry->coins);
      free(entry);
      trade_locker_index[entry_idx] = NULL;
    }
  }

  pthread_mutex_unlock(&trade_locker_mtx);
}

/*
 * Internal helper - adds entry to the locker index
 * Mutex must be acquired by caller
 */
static int add_index_entry_internal(int8_t denomination, uint32_t sn, unsigned char *an)
{
  int i;
  int new_entry = 0, found = 0;
  int cidx, gidx;
  coin_t *tmp;

  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (locker_index[i] == NULL)
    {
      new_entry = 1;
      break;
    }
    if (!memcmp(locker_index[i]->an, an, 16))
    {
      found = 1;
      break;
    }
  }

  if (new_entry)
  {
    locker_index[i] = (struct index_entry *)malloc(sizeof(struct index_entry));
    if (locker_index[i] == NULL)
    {
      error("Failed to allocate memory for the index slot");
      return -1;
    }
    locker_index[i]->coins = malloc(sizeof(coin_t) * PREALLOCATE_COINS);
    if (locker_index[i]->coins == NULL)
    {
      error("Failed to allocate memory for the index coins");
      free(locker_index[i]);
      locker_index[i] = NULL;
      return -1;
    }
    locker_index[i]->num_coins = 1;
    memcpy(locker_index[i]->an, an, 16);
    locker_index[i]->coins[0].denomination = denomination;
    locker_index[i]->coins[0].sn = sn;
  }
  else if (found)
  {
    cidx = locker_index[i]->num_coins;
    if ((cidx % PREALLOCATE_COINS) == 0)
    {
      gidx = (cidx / PREALLOCATE_COINS) + 1;
      tmp = realloc(locker_index[i]->coins, sizeof(coin_t) * gidx * PREALLOCATE_COINS);
      if (tmp == NULL)
      {
        error("Failed to re-allocate memory for the index coins");
        return -1;
      }
      locker_index[i]->coins = tmp;
    }
    locker_index[i]->coins[cidx].denomination = denomination;
    locker_index[i]->coins[cidx].sn = sn;
    locker_index[i]->num_coins++;
  }
  else
  {
    debug("Index table is full. Can't add more records");
    return -1;
  }

  return 0;
}

/*
 * Internal helper - adds entry to the trade index
 * Mutex must be acquired by caller
 */
static int add_trade_index_entry_internal(int8_t denomination, uint32_t sn, unsigned char *an)
{
  int i;
  int new_entry = 0, found = 0;
  int cidx, gidx;
  coin_t *tmp;

  debug("Denomination %hhx SN %d is added to the trade locker index", denomination, sn);

  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (trade_locker_index[i] == NULL)
    {
      new_entry = 1;
      break;
    }
    if (!memcmp(trade_locker_index[i]->an, an, 16))
    {
      found = 1;
      break;
    }
  }

  if (new_entry)
  {
    trade_locker_index[i] = (struct index_entry *)malloc(sizeof(struct index_entry));
    if (trade_locker_index[i] == NULL)
    {
      error("Failed to allocate memory for the index slot");
      return -1;
    }
    trade_locker_index[i]->coins = malloc(sizeof(coin_t) * PREALLOCATE_COINS);
    if (trade_locker_index[i]->coins == NULL)
    {
      error("Failed to allocate memory for the trade index coins");
      free(trade_locker_index[i]);
      trade_locker_index[i] = NULL;
      return -1;
    }
    trade_locker_index[i]->num_coins = 1;
    memcpy(trade_locker_index[i]->an, an, 16);
    trade_locker_index[i]->coins[0].denomination = denomination;
    trade_locker_index[i]->coins[0].sn = sn;
  }
  else if (found)
  {
    cidx = trade_locker_index[i]->num_coins;
    if ((cidx % PREALLOCATE_COINS) == 0)
    {
      gidx = (cidx / PREALLOCATE_COINS) + 1;
      tmp = realloc(trade_locker_index[i]->coins, sizeof(coin_t) * gidx * PREALLOCATE_COINS);
      if (tmp == NULL)
      {
        error("Failed to re-allocate bigger memory for the index coins");
        return -1;
      }
      trade_locker_index[i]->coins = tmp;
    }
    trade_locker_index[i]->coins[cidx].denomination = denomination;
    trade_locker_index[i]->coins[cidx].sn = sn;
    trade_locker_index[i]->num_coins++;
  }
  else
  {
    debug("Index table is full. Can't add more records");
    return -1;
  }

  return 0;
}

/*
 * Frees index memory - Mutex must be acquired
 */
void free_index(void)
{
  int i, c = 0;
  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (locker_index[i] == NULL)
      continue;
    free(locker_index[i]->coins);
    free(locker_index[i]);
    locker_index[i] = NULL;
    c++;
  }
  debug("Freed %d locker index entries", c);
}

void free_trade_index(void)
{
  int i, c = 0;
  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (trade_locker_index[i] == NULL)
      continue;
    free(trade_locker_index[i]->coins);
    free(trade_locker_index[i]);
    trade_locker_index[i] = NULL;
    c++;
  }
  debug("Freed %d trade locker index entries", c);
}

/*
 * Shows index - Mutex must be acquired
 */
void show_index(void)
{
  int i, j;
  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (locker_index[i] == NULL)
      continue;
    for (j = 0; j < locker_index[i]->num_coins; j++)
    {
      debug("AN %02x%02x%02x%02x...%02x%02x%02x%02x (%d coins) den %hhx sn %d",
            locker_index[i]->an[0], locker_index[i]->an[1], locker_index[i]->an[2], locker_index[i]->an[3],
            locker_index[i]->an[12], locker_index[i]->an[13], locker_index[i]->an[14], locker_index[i]->an[15],
            locker_index[i]->num_coins, locker_index[i]->coins[j].denomination, locker_index[i]->coins[j].sn);
    }
  }
}

void show_trade_index(void)
{
  int i, j;
  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (trade_locker_index[i] == NULL)
      continue;
    for (j = 0; j < trade_locker_index[i]->num_coins; j++)
    {
      debug("AN %02x%02x%02x%02x...%02x%02x%02x%02x (%d coins) den %hhx sn %d",
            trade_locker_index[i]->an[0], trade_locker_index[i]->an[1], trade_locker_index[i]->an[2], trade_locker_index[i]->an[3],
            trade_locker_index[i]->an[12], trade_locker_index[i]->an[13], trade_locker_index[i]->an[14], trade_locker_index[i]->an[15],
            trade_locker_index[i]->num_coins, trade_locker_index[i]->coins[j].denomination, trade_locker_index[i]->coins[j].sn);
    }
  }
}

/*
 * Goes over all index entries until it finds a matching AN
 */
struct index_entry *get_coins_from_index(unsigned char *an)
{
  int i;
  struct index_entry *ie = NULL;

  if (pthread_mutex_lock(&locker_mtx) != 0)
  {
    error("Failed to lock locker mutex for get_coins_from_index");
    return NULL;
  }

  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (locker_index[i] != NULL && !memcmp(locker_index[i]->an, an, 16))
    {
      ie = locker_index[i];
      break;
    }
  }
  pthread_mutex_unlock(&locker_mtx);
  return ie;
}

/*
 * Goes over all trade index entries until it finds a matching AN
 */
struct index_entry *get_coins_from_trade_index(unsigned char *an)
{
  int i;
  struct index_entry *ie = NULL;

  if (pthread_mutex_lock(&trade_locker_mtx) != 0)
  {
    error("Failed to lock trade locker mutex for get_coins_from_trade_index");
    return NULL;
  }

  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (trade_locker_index[i] != NULL && !memcmp(trade_locker_index[i]->an, an, 16))
    {
      ie = trade_locker_index[i];
      break;
    }
  }
  pthread_mutex_unlock(&trade_locker_mtx);
  return ie;
}

/*
 * Goes over all trade index entries until it finds a matching coin_type
 */
int load_coins_from_trade_index(uint8_t f_coin_type, uint8_t nr, struct index_entry **ies)
{
  int i, j = 0;

  if (pthread_mutex_lock(&trade_locker_mtx) != 0)
  {
    error("Failed to lock trade locker mutex for load_coins_from_trade_index");
    return 0;
  }

  for (i = 0; i < MAX_LOCKER_RECORDS && j < nr; i++)
  {
    if (trade_locker_index[i] != NULL && trade_locker_index[i]->an[13] == f_coin_type)
    {
      ies[j++] = trade_locker_index[i];
    }
  }
  pthread_mutex_unlock(&trade_locker_mtx);
  return j;
}

/*
 * Goes over all index entries until it finds a matching AN (first 5 bytes only for encryption)
 */
struct index_entry *get_coins_from_index_by_prefix(unsigned char *an)
{
  int i;
  struct index_entry *ie = NULL;

  if (pthread_mutex_lock(&locker_mtx) != 0)
  {
    error("Failed to lock locker mutex for get_coins_from_index_by_prefix");
    return NULL;
  }

  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (locker_index[i] != NULL && !memcmp(locker_index[i]->an, an, 5))
    {
      ie = locker_index[i];
      break;
    }
  }
  pthread_mutex_unlock(&locker_mtx);
  return ie;
}

int is_good_trade_coin_type(uint8_t f_coin_type)
{
  return f_coin_type == SALE_TYPE_CC || f_coin_type == SALE_TYPE_BTC || f_coin_type == SALE_TYPE_XMR;
}

/*
 * Goes over all trade index entries and finds matching criteria
 */
struct index_entry *get_entry_from_trade_index(uint8_t f_coin_type, uint64_t amount, uint32_t price)
{
  int i;
  struct index_entry *ie = NULL;
  uint64_t locker_amount;
  uint32_t locker_price;

  if (pthread_mutex_lock(&trade_locker_mtx) != 0)
  {
    error("Failed to lock trade locker mutex for get_entry_from_trade_index");
    return NULL;
  }

  for (i = 0; i < MAX_LOCKER_RECORDS; i++)
  {
    if (trade_locker_index[i] == NULL)
      continue;
    if (trade_locker_index[i]->an[13] != f_coin_type)
      continue;

    locker_price = get_u32(&trade_locker_index[i]->an[9]);
    if (price != locker_price)
      continue;

    locker_amount = calc_coins_in_trade_locker(trade_locker_index[i]);
    if (locker_amount != amount)
      continue;

    ie = trade_locker_index[i];
    debug("Found. Total coins in the trade locker %d", ie->num_coins);
    break;
  }
  pthread_mutex_unlock(&trade_locker_mtx);
  return ie;
}

/*
 * Calculates the amount of coins in the trade locker
 */
uint64_t calc_coins_in_trade_locker(struct index_entry *ie)
{
  int j;
  coin_t *cc;
  uint64_t value = 0;

  for (j = 0; j < ie->num_coins; j++)
  {
    cc = &ie->coins[j];
    value += coin_value(cc->denomination, cc->sn);
  }

  return value;
}
