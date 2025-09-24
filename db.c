/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : db.c
#   Last Modified : 2025-08-07
#   Describe      : This file implements the On-Demand Page Cache database layer.
#                 ** CONCURRENCY FIXES APPLIED to resolve deadlocks and race conditions. **
#
# ====================================================*/

#define _GNU_SOURCE
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <stdint.h>

#include "config.h"
#include "db.h"
#include "log.h"
#include "utils.h"
#include "protocol.h"

#define MAX_CACHED_PAGES 5000
#define HASH_TABLE_SIZE 2048
#define TOTAL_COINS_PER_DENOMINATION (TOTAL_PAGES * RECORDS_PER_PAGE)
#define BITMAP_SIZE_BYTES (TOTAL_COINS_PER_DENOMINATION / 8)

extern struct config_s config;
extern int is_finished;

typedef struct page_cache_entry
{
  struct page_s *page;
  uint32_t key;
  struct page_cache_entry *next;
} page_cache_entry_t;

static page_cache_entry_t *page_cache_hash_table[HASH_TABLE_SIZE];
static struct page_s *lru_head = NULL;
static struct page_s *lru_tail = NULL;
static int cached_pages_count = 0;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t persistence_thread_handle;

// ** NEW: Condition variable and mutex for clean shutdown **
static pthread_cond_t persistence_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t persistence_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint8_t *free_pages_bitmap[TOTAL_DENOMINATIONS];
static pthread_mutex_t bitmap_mutexes[TOTAL_DENOMINATIONS];

// Forward declarations
static void cache_add(uint32_t key, struct page_s *page);
static struct page_s *cache_lookup(uint32_t key);
static struct page_s *cache_evict_and_get_victim(void);
static void lru_move_to_front(struct page_s *page);
static struct page_s *load_page_from_disk(int8_t denomination, uint16_t page_no);

int init_db(void)
{
  pthread_t persistence_thread;
  debug("Initializing On-Demand Page Cache database layer");

  memset(page_cache_hash_table, 0, sizeof(page_cache_hash_table));

  int rr = rand();
  for (int i = MIN_DENOMINATION; i <= MAX_DENOMINATION; i++)
  {
    for (int j = 0; j < TOTAL_PAGES; j++)
    {
      if (init_page(rr, i, j) < 0)
      {
        error("Failed to ensure page file exists for den %d, page %d", i, j);
        return -1;
      }
    }
  }

  if (init_free_pages_bitmap() != 0)
  {
    error("Failed to initialize the free pages bitmap");
    return -1;
  }

  if (pthread_create(&persistence_thread_handle, NULL, persistence_and_eviction_thread, NULL) < 0)
  {
    error("Failed to start persistence and eviction thread: %s", strerror(errno));
    return -1;
  }

  debug("Database layer initialized successfully.");
  return 0;
}

int init_free_pages_bitmap(void)
{
  debug("Initializing free pages bitmap using direct disk access...");
  for (int i = 0; i < TOTAL_DENOMINATIONS; i++)
  {
    int8_t den = get_den_by_idx(i);
    if (pthread_mutex_init(&bitmap_mutexes[i], NULL) != 0)
    {
      error("Failed to initialize bitmap mutex for denomination %d", den);
      return -1;
    }

    free_pages_bitmap[i] = (uint8_t *)calloc(BITMAP_SIZE_BYTES, sizeof(uint8_t));
    if (free_pages_bitmap[i] == NULL)
    {
      error("Failed to allocate memory for bitmap for denomination %d", den);
      return -1;
    }

    for (int j = 0; j < TOTAL_PAGES; j++)
    {
      // Use direct disk access - this bypasses the cache completely
      struct page_s *page = read_page_direct_from_disk(den, j);
      if (page == NULL)
      {
        error("Failed to read page %d for denomination %d during bitmap initialization", j, den);
        continue;
      }

      for (int k = 0; k < RECORDS_PER_PAGE; k++)
      {
        if (page->data[k * 17 + 16] != 0) // // MFS != 0 means IN USE
        {
          uint32_t sn = j * RECORDS_PER_PAGE + k;
          int byte_idx = sn / 8;
          int bit_idx = sn % 8;
          free_pages_bitmap[i][byte_idx] |= (1 << bit_idx); // Set bit to 1 for IN USE
        }
      }

      // This is a real free - page was never added to cache
      free(page);
    }
  }
  debug("Free pages bitmap initialized successfully using direct disk access.");
  return 0;
}
int update_free_pages_bitmap(int8_t denomination, uint32_t sn, int is_free)
{
  int den_idx = get_den_idx(denomination);
  if (den_idx < 0 || den_idx >= TOTAL_DENOMINATIONS)
  {
    error("Invalid denomination %d for bitmap update", denomination);
    return -1;
  }

  int byte_idx = sn / 8;
  int bit_idx = sn % 8;

  if (byte_idx >= BITMAP_SIZE_BYTES)
  {
    error("SN %u out of bounds for bitmap", sn);
    return -1;
  }

  // Use a blocking lock to GUARANTEE consistency. A timeout would lead to a corrupted bitmap.
  // The operation is extremely fast, so blocking is not a performance issue.
  if (pthread_mutex_lock(&bitmap_mutexes[den_idx]) != 0)
  {
    error("Failed to lock bitmap mutex for denomination %d", denomination);
    return -1; // Critical error
  }

  if (is_free)
  {
    free_pages_bitmap[den_idx][byte_idx] |= (1 << bit_idx); // Set bit to 1
  }
  else
  {
    free_pages_bitmap[den_idx][byte_idx] &= ~(1 << bit_idx); // Clear bit to 0
  }

  if (pthread_mutex_unlock(&bitmap_mutexes[den_idx]) != 0)
  {
    error("Failed to unlock bitmap mutex for denomination %d", denomination);
    // This is a serious issue, the mutex is now in an inconsistent state.
  }

  return 0;
}

int get_available_sns_from_bitmap(int8_t denomination, uint32_t *sns, int max_sns)
{
  int den_idx = get_den_idx(denomination);
  int count = 0;

  pthread_mutex_lock(&bitmap_mutexes[den_idx]);
  for (uint32_t i = 0; i < TOTAL_COINS_PER_DENOMINATION && count < max_sns; i++)
  {
    int byte_idx = i / 8;
    int bit_idx = i % 8;
    if (!((free_pages_bitmap[den_idx][byte_idx] >> bit_idx) & 1)) // Bit is 0 = FREE
    {
      sns[count++] = i;
    }
  }
  pthread_mutex_unlock(&bitmap_mutexes[den_idx]);

  return count;
}

struct page_s *get_page_by_sn_lock(int8_t denomination, uint32_t sn)
{
  uint16_t page_no = sn / RECORDS_PER_PAGE;
  uint32_t key = (get_den_idx(denomination) << 16) | page_no;
  struct page_s *page = NULL;
  struct page_s *victim_to_free = NULL;

  // Phase 1: Cache management (lookup, load, evict). Protected by the global cache_mutex.
  if (pthread_mutex_lock(&cache_mutex) != 0)
  {
    error("Failed to lock cache mutex for den:%d sn:%u", denomination, sn);
    return NULL;
  }

  page = cache_lookup(key);
  if (page)
  {
    lru_move_to_front(page);
  }
  else
  {
    if (cached_pages_count >= MAX_CACHED_PAGES)
    {
      victim_to_free = cache_evict_and_get_victim();
    }

    // Temporarily unlock cache to perform slow disk I/O
    pthread_mutex_unlock(&cache_mutex);

    page = load_page_from_disk(denomination, page_no);

    // Re-lock cache to safely add the new page
    if (pthread_mutex_lock(&cache_mutex) != 0)
    {
      error("Failed to re-lock cache mutex after disk I/O");
      if (page)
        free(page);
      if (victim_to_free)
        free(victim_to_free); // Prevent memory leak
      return NULL;
    }

    if (page)
    {
      cache_add(key, page);
    }
  }

  pthread_mutex_unlock(&cache_mutex);

  // Sync and free the evicted victim page *after* releasing the global cache lock.
  if (victim_to_free)
  {
    if (victim_to_free->is_dirty)
    {
      sync_page(victim_to_free);
    }
    pthread_mutex_destroy(&victim_to_free->mtx);
    free(victim_to_free);
  }

  // Phase 2: Lock the specific page. This is done outside the global cache lock to prevent deadlocks.
  if (page)
  {
    if (pthread_mutex_lock(&page->mtx) != 0)
    {
      error("Failed to lock page mutex for den:%d sn:%u", denomination, sn);
      // If we fail to lock the page, we don't hold any other locks, so it's safe to just return.
      // The page remains in the cache for other threads to use.
      return NULL;
    }
  }

  return page;
}

void unlock_page(struct page_s *page)
{
  if (page)
  {
    if (pthread_mutex_unlock(&page->mtx) != 0)
    {
      error("Failed to unlock page mutex for den:%d no:%d", page->denomination, page->no);
    }
  }
}

// void *persistence_and_eviction_thread(void *arg)
// {
//   debug("Starting persistence and eviction thread.");
//   struct page_s *dirty_pages[MAX_CACHED_PAGES];
//   int dirty_count;

//   while (!is_finished)
//   {
//     sleep(config.flush_freq);
//     debug("Persistence thread waking up to sync dirty pages.");

//     dirty_count = 0;

//     pthread_mutex_lock(&cache_mutex);
//     struct page_s *current = lru_head;
//     while (current && dirty_count < MAX_CACHED_PAGES)
//     {
//       if (current->is_dirty)
//       {
//         dirty_pages[dirty_count] = current;
//         dirty_count++;
//       }
//       current = current->next;
//     }
//     pthread_mutex_unlock(&cache_mutex);

//     if (dirty_count > 0)
//     {
//       debug("Found %d dirty pages to sync.", dirty_count);
//       for (int i = 0; i < dirty_count; i++)
//       {
//         sync_page(dirty_pages[i]);
//         // Note: is_dirty is reset inside sync_page after a successful write
//       }
//       debug("Finished syncing dirty pages.");
//     }
//   }
//   debug("Persistence and eviction thread shutting down.");
//   return NULL;
// }

void *persistence_and_eviction_thread(void *arg)
{
  debug("Starting persistence and eviction thread.");
  struct page_s *dirty_pages[MAX_CACHED_PAGES];
  int dirty_count;

  while (!is_finished)
  {
    // ** NEW: Use timed wait on condition variable instead of sleep **
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += config.flush_freq;

    pthread_mutex_lock(&persistence_mutex);
    pthread_cond_timedwait(&persistence_cond, &persistence_mutex, &ts);
    pthread_mutex_unlock(&persistence_mutex);

    if (is_finished)
      break;

    debug("Persistence thread waking up to sync dirty pages.");

    dirty_count = 0;
    pthread_mutex_lock(&cache_mutex);
    struct page_s *current = lru_head;
    while (current && dirty_count < MAX_CACHED_PAGES)
    {
      if (current->is_dirty)
      {
        dirty_pages[dirty_count] = current;
        dirty_count++;
      }
      current = current->next;
    }
    pthread_mutex_unlock(&cache_mutex);

    if (dirty_count > 0)
    {
      debug("Found %d dirty pages to sync.", dirty_count);
      for (int i = 0; i < dirty_count; i++)
      {
        sync_page(dirty_pages[i]);
      }
      debug("Finished syncing dirty pages.");
    }
  }
  debug("Persistence and eviction thread shutting down.");
  return NULL;
}

static void lru_move_to_front(struct page_s *page)
{
  if (page == lru_head)
    return;

  if (page->prev)
    page->prev->next = page->next;
  if (page->next)
    page->next->prev = page->prev;
  if (page == lru_tail)
    lru_tail = page->prev;

  page->next = lru_head;
  page->prev = NULL;
  if (lru_head)
    lru_head->prev = page;
  lru_head = page;
  if (lru_tail == NULL)
    lru_tail = page;
}

static void cache_add(uint32_t key, struct page_s *page)
{
  unsigned int hash_index = key % HASH_TABLE_SIZE;
  page_cache_entry_t *new_entry = malloc(sizeof(page_cache_entry_t));
  if (!new_entry)
  {
    error("Failed to allocate memory for cache entry");
    // The page will be leaked here, but crashing is worse.
    return;
  }
  new_entry->key = key;
  new_entry->page = page;
  new_entry->next = page_cache_hash_table[hash_index];
  page_cache_hash_table[hash_index] = new_entry;

  page->next = lru_head;
  page->prev = NULL;
  if (lru_head)
    lru_head->prev = page;
  lru_head = page;
  if (lru_tail == NULL)
    lru_tail = page;

  cached_pages_count++;
}

static struct page_s *cache_lookup(uint32_t key)
{
  unsigned int hash_index = key % HASH_TABLE_SIZE;
  page_cache_entry_t *entry = page_cache_hash_table[hash_index];
  while (entry)
  {
    if (entry->key == key)
      return entry->page;
    entry = entry->next;
  }
  return NULL;
}

static struct page_s *cache_evict_and_get_victim()
{
  if (lru_tail == NULL)
    return NULL;

  struct page_s *victim = lru_tail;
  debug("Cache full. Evicting page den:%d no:%d", victim->denomination, victim->no);

  lru_tail = victim->prev;
  if (lru_tail)
    lru_tail->next = NULL;
  if (lru_head == victim)
    lru_head = NULL;

  uint32_t key = (get_den_idx(victim->denomination) << 16) | victim->no;
  unsigned int hash_index = key % HASH_TABLE_SIZE;
  page_cache_entry_t *entry = page_cache_hash_table[hash_index];
  page_cache_entry_t *prev = NULL;
  while (entry)
  {
    if (entry->key == key)
    {
      if (prev)
        prev->next = entry->next;
      else
        page_cache_hash_table[hash_index] = entry->next;
      free(entry);
      break;
    }
    prev = entry;
    entry = entry->next;
  }

  cached_pages_count--;
  return victim;
}

static struct page_s *load_page_from_disk(int8_t denomination, uint16_t page_no)
{
  char page_path[PATH_MAX];
  uint8_t page_msb = (page_no >> 8) & 0xff;
  snprintf(page_path, sizeof(page_path), "%s/Data/%02hhx/%02x/%04x.bin", config.cwd, (uint8_t)denomination, page_msb, page_no);

  int fd = open(page_path, O_RDONLY);
  if (fd < 0)
  {
    error("Failed to open page file for loading %s: %s", page_path, strerror(errno));
    return NULL;
  }

  struct page_s *page = malloc(sizeof(struct page_s));
  if (!page)
  {
    error("Failed to allocate memory for new page");
    close(fd);
    return NULL;
  }

  ssize_t bytes_read = read(fd, page->data, sizeof(page->data));
  close(fd);

  if (bytes_read != sizeof(page->data))
  {
    error("Failed to read full page from disk %s", page_path);
    free(page);
    return NULL;
  }

  page->denomination = denomination;
  page->no = page_no;
  page->is_dirty = 0;
  page->reserved_at = 0;
  page->reserved_by = 0;
  if (pthread_mutex_init(&page->mtx, NULL) != 0)
  {
    error("Failed to initialize page mutex for den:%d no:%d", denomination, page_no);
    free(page);
    return NULL;
  }
  page->prev = page->next = NULL;

  debug("Loaded page den:%d no:%d from disk into cache.", denomination, page_no);
  return page;
}

static struct page_s *read_page_direct_from_disk(int8_t denomination, uint16_t page_no)
{
  char page_path[PATH_MAX];
  uint8_t page_msb = (page_no >> 8) & 0xff;
  snprintf(page_path, sizeof(page_path), "%s/Data/%02hhx/%02x/%04x.bin", config.cwd, (uint8_t)denomination, page_msb, page_no);

  int fd = open(page_path, O_RDONLY);
  if (fd < 0)
  {
    error("Failed to open page file for direct reading %s: %s", page_path, strerror(errno));
    return NULL;
  }

  struct page_s *page = malloc(sizeof(struct page_s));
  if (!page)
  {
    error("Failed to allocate memory for direct page read");
    close(fd);
    return NULL;
  }

  ssize_t bytes_read = read(fd, page->data, sizeof(page->data));
  close(fd);

  if (bytes_read != sizeof(page->data))
  {
    error("Failed to read full page from disk %s", page_path);
    free(page);
    return NULL;
  }

  // Only set essential fields - this is not a cached page
  page->denomination = denomination;
  page->no = page_no;
  // Don't initialize mutex, cache pointers, or other cache-related fields

  debug("Read page den:%d no:%d directly from disk for initialization", denomination, page_no);
  return page;
}

int init_page(int seed, int8_t denomination, int page_no)
{
  uint8_t page_msb = (page_no >> 8) & 0xff;
  char data_path[PATH_MAX];
  char den_path[PATH_MAX];
  char page_msb_path[PATH_MAX];
  char page_path[PATH_MAX];

  snprintf(data_path, sizeof(data_path), "%s/Data", config.cwd);
  snprintf(den_path, sizeof(den_path), "%s/%02hhx", data_path, (uint8_t)denomination);
  snprintf(page_msb_path, sizeof(page_msb_path), "%s/%02x", den_path, page_msb);
  snprintf(page_path, sizeof(page_path), "%s/%04x.bin", page_msb_path, page_no);

  if (access(page_path, F_OK) == 0)
    return 0;

  debug("Page file not found, creating directory structure for: %s", page_path);

  if (mkdir(data_path, 0755) != 0 && errno != EEXIST)
  {
    error("Failed to create base Data folder %s: %s", data_path, strerror(errno));
    return -1;
  }
  if (mkdir(den_path, 0755) != 0 && errno != EEXIST)
  {
    error("Failed to create denomination folder %s: %s", den_path, strerror(errno));
    return -1;
  }
  if (mkdir(page_msb_path, 0755) != 0 && errno != EEXIST)
  {
    error("Failed to create page MSB folder %s: %s", page_msb_path, strerror(errno));
    return -1;
  }

  unsigned char *buf = malloc(RECORDS_PER_PAGE * 17);
  if (!buf)
  {
    error("Failed to allocate memory for page initialization.");
    return -1;
  }

  for (int i = 0; i < RECORDS_PER_PAGE; i++)
  {
    unsigned char input[64];
    int len = snprintf((char *)input, sizeof(input), "%02x%02x%04x%02x", seed & 0xffff, denomination, page_no, i);
    generate_an_hash_legacy(input, len, buf + (i * 17));
    buf[i * 17 + 16] = 0;
  }

  int fd = open(page_path, O_CREAT | O_WRONLY, 0640);
  if (fd < 0)
  {
    error("Failed to create page file %s: %s", page_path, strerror(errno));
    free(buf);
    return -1;
  }

  ssize_t written = write(fd, buf, RECORDS_PER_PAGE * 17);
  close(fd);
  free(buf);

  if (written != RECORDS_PER_PAGE * 17)
  {
    error("Failed to write full page data to %s", page_path);
    return -1;
  }

  return 0;
}

void sync_page(struct page_s *page)
{
  char page_path[PATH_MAX];
  uint8_t page_msb = (page->no >> 8) & 0xff;
  snprintf(page_path, sizeof(page_path), "%s/Data/%02hhx/%02x/%04x.bin", config.cwd, page->denomination, page_msb, page->no);

  if (pthread_mutex_lock(&page->mtx) != 0)
  {
    error("Failed to lock page mutex for syncing den:%d no:%d", page->denomination, page->no);
    return;
  }

  // Only write if the page is actually dirty
  if (!page->is_dirty)
  {
    pthread_mutex_unlock(&page->mtx);
    return;
  }

  int fd = open(page_path, O_WRONLY);
  if (fd < 0)
  {
    error("Failed to open page file for syncing %s: %s", page_path, strerror(errno));
    pthread_mutex_unlock(&page->mtx);
    return;
  }

  ssize_t written = -1;
  int retries = 3;
  while (retries > 0)
  {
    written = write(fd, page->data, sizeof(page->data));
    if (written == sizeof(page->data))
    {
      page->is_dirty = 0; // Reset dirty flag ONLY on successful write
      break;
    }
    error("Failed to write full page to disk %s (retrying): %s", page_path, strerror(errno));
    retries--;
    usleep(100000); // 100ms delay
  }

  close(fd);
  pthread_mutex_unlock(&page->mtx);

  if (written != sizeof(page->data))
  {
    error("FATAL: Failed to write full page to disk %s after multiple retries. The bitmap may be out of sync.", page_path);
  }
}

void reserve_page(struct page_s *page, uint32_t sid)
{
  debug("Reserving page %d for denomination %hhx with sid %x", page->no, page->denomination, sid);
  page->reserved_by = sid;
  time(&page->reserved_at);
}

int page_is_reserved(struct page_s *page)
{
  if (!page->reserved_at || !page->reserved_by)
    return 0;
  if (difftime(time(NULL), page->reserved_at) > RESERVED_PAGE_RELEASE_SECONDS)
  {
    release_reserved_page(page);
    return 0;
  }
  return 1;
}

void release_reserved_page(struct page_s *page)
{
  debug("Releasing reserved page %d", page->no);
  page->reserved_by = 0;
  page->reserved_at = 0;
}

// void cleanup_db_threads(void)
// {
//   debug("Shutting down database persistence thread...");
//   if (pthread_join(persistence_thread_handle, NULL) != 0)
//   {
//     error("Failed to join persistence thread");
//   }
//   debug("Database persistence thread shut down cleanly.");
// }

void cleanup_db_threads(void)
{
  debug("Shutting down database persistence thread...");
  // ** NEW: Signal the thread to wake up from its timed wait **
  pthread_mutex_lock(&persistence_mutex);
  pthread_cond_signal(&persistence_cond);
  pthread_mutex_unlock(&persistence_mutex);

  if (pthread_join(persistence_thread_handle, NULL) != 0)
  {
    error("Failed to join persistence thread");
  }
  debug("Database persistence thread shut down cleanly.");
}

int get_den_idx(int8_t den) { return den + DENOMINATION_OFFSET; }
int8_t get_den_by_idx(int den_idx) { return (int8_t)(den_idx - DENOMINATION_OFFSET); }