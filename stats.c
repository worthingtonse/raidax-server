/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium 
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : db.c
#   Last Modified : 2023-06-01 15:18
#   Describe      : This file implements the Coin Database Layer
#
# ====================================================*/

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
#include "md5.h"
#include "protocol.h"
#include "stats.h"


// Main Structure for Coins in RAM
struct stats_s stats;

// Mutex to protect the main structure
pthread_mutex_t stats_mtx;

/*
 * Initializes page files
 */
int init_stats(void) {

  debug("Initializing stats layer");


  pthread_mutex_init(&stats_mtx, NULL);
  memset(&stats, 0, sizeof(struct stats_s));

  return 0;
}


/*
 * Increments stat field
 */
void inc_stat(int idx, uint64_t v) {
  pthread_mutex_lock(&stats_mtx);
  switch(idx) {
    case ECHO_FIELD_IDX:
      stats.echo_cnt += v ;
      break;
    case POWN_FIELD_IDX:
      stats.pown_cnt += v;
      break;
    case POWN_VALUE_FIELD_IDX:
      stats.pown_value_cnt += v;
      break;
    case REQUESTS_FIELD_IDX:
      stats.requests_value_cnt += v;
      break;
  }

  pthread_mutex_unlock(&stats_mtx);
}

/*
 * Copies all stats
 */
void copy_stats(unsigned char *buf) {
  pthread_mutex_lock(&stats_mtx);
  memcpy(buf, &stats, sizeof(struct stats_s));
  pthread_mutex_unlock(&stats_mtx);
}

