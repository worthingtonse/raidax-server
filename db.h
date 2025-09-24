/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : db.h
#   Last Modified : 2025-07-24 11:03
#   Describe      : Database Layer Header for On-Demand Page Cache with Free Pages Bitmap
#
# ====================================================*/

#ifndef _DB_H
#define _DB_H

#include <pthread.h>
#include <stdint.h>
#include <time.h>

// Initialize the database system, including the page cache and background threads.
int init_db(void);
// Creates the physical file for a page if it doesn't exist.
int init_page(int seed, int8_t denomination, int page_no);

//  Bitmap for tracking free pages **
int init_free_pages_bitmap(void);
int update_free_pages_bitmap(int8_t denomination, uint32_t sn, int is_free);
int get_available_sns_from_bitmap(int8_t denomination, uint32_t *sns, int max_sns);

enum denominations
{
  DEN_0_00000001 = -8,
  DEN_0_0000001 = -7,
  DEN_0_000001 = -6,
  DEN_0_00001 = -5,
  DEN_0_0001 = -4,
  DEN_0_001 = -3,
  DEN_0_01 = -2,
  DEN_0_1 = -1,
  DEN_1 = 0,
  DEN_10 = 1,
  DEN_100 = 2,
  DEN_1000 = 3,
  DEN_10000 = 4,
  DEN_100000 = 5,
  DEN_1000000 = 6
};

#define MIN_DENOMINATION DEN_0_00000001
#define MAX_DENOMINATION DEN_1000000
#define TOTAL_DENOMINATIONS 15
#define DENOMINATION_OFFSET 8

// The total number of possible pages per denomination. This is used for file naming and SN calculation.
#define TOTAL_PAGES 1000
// The number of coin records per page.
#define RECORDS_PER_PAGE 1024

/*
 * ** RE-ARCHITECTED: The page_s struct is now a node in a cache. **
 * This struct represents a single page of coin data that is currently loaded into RAM.
 * It is designed to be part of a hash map (for fast lookups) and a doubly-linked list
 * (for managing the LRU eviction policy).
 */
struct page_s
{
  // Core Data
  unsigned char data[RECORDS_PER_PAGE * 17]; // The actual coin data (ANs and MFS)
  int8_t denomination;
  uint16_t no; // The page number

  // Concurrency and State Management
  pthread_mutex_t mtx; // Lock for this specific page
  int is_dirty;        // Flag indicating if the page has been modified since being loaded

  // Client Reservation Fields
  time_t reserved_at;
  uint32_t reserved_by;

  //: Pointers for the LRU (Least Recently Used) cache linked list **
  struct page_s *prev; // Pointer to the previous page in the LRU list
  struct page_s *next; // Pointer to the next page in the LRU list
};

// : Main function for accessing a page. **
// This function will get a page from the cache. If the page is not in the cache (a "cache miss"),
// it will load it from the disk. It returns the page in a locked state.
struct page_s *get_page_by_sn_lock(int8_t denomination, uint32_t sn);

// Releases the lock on a page, allowing other threads to access it.
void unlock_page(struct page_s *page);

static struct page_s *read_page_direct_from_disk(int8_t denomination, uint16_t page_no);

// Functions for managing client-side page reservations.
int page_is_reserved(struct page_s *page);
void reserve_page(struct page_s *page, uint32_t sid);
void release_reserved_page(struct page_s *page);

// : Background thread for managing the cache and persisting data. **
// This thread will handle both writing dirty pages to disk and evicting
// least-recently-used pages from the cache if it exceeds its memory limit.
void *persistence_and_eviction_thread(void *arg);

// Writes a single page's data to its corresponding file on disk.
void sync_page(struct page_s *page);

// Utility functions for converting between denomination ID and array index.
int get_den_idx(int8_t den);
int8_t get_den_by_idx(int den_idx);
void cleanup_db_threads(void);

#define RESERVED_PAGE_RELEASE_SECONDS 16

#endif // _DB_H