/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium 
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : db.h
#   Last Modified : 2023-04-30 10:20
#   Describe      : Stats Layer Header
#
# ====================================================*/

#ifndef  _STATS_H
#define  _STATS_H

#include <pthread.h>

// Main structure
struct stats_s {
  uint64_t echo_cnt;
  uint64_t pown_cnt;
  uint64_t pown_value_cnt;
  uint64_t requests_value_cnt;
};


int init_stats(void);
void inc_stat(int, uint64_t);
void copy_stats(unsigned char *);

#define ECHO_FIELD_IDX 0
#define POWN_FIELD_IDX 1
#define POWN_VALUE_FIELD_IDX 2
#define REQUESTS_FIELD_IDX 3

#define MAX_FIELD_IDX REQUESTS_FIELD_IDX

#endif // _STATS_H


