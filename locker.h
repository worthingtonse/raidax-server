/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : locker.h
#   Last Modified : 2025-01-07 10:54
#   Describe      : Locker header file
#
# ====================================================*/

#ifndef _LOCKER_H
#define _LOCKER_H

#include "protocol.h"

// Maximum locker records that the index can keep
#define MAX_LOCKER_RECORDS 100000

// How often we update the index (No longer used for periodic rebuilds)
#define INDEX_UPDATE_PERIOD 3600

int init_locker_index(void);
void build_initial_locker_indices(void);

// Incremental update functions for the locker index **
void locker_index_add_coins(unsigned char *an, coin_t *coins_to_add, int num_coins);
void locker_index_remove_coins(unsigned char *an, coin_t *coins_to_remove, int num_coins);

//  Incremental update functions for the trade locker index **
void trade_locker_index_add_coins(unsigned char *an, coin_t *coins_to_add, int num_coins);
void trade_locker_index_remove_coins(unsigned char *an, coin_t *coins_to_remove, int num_coins);

void free_index(void);
void free_trade_index(void);
void show_index(void);
void show_trade_index(void);

#define PREALLOCATE_COINS 2
struct index_entry
{
  unsigned char an[16];
  int num_coins;
  coin_t *coins;
};

struct index_entry *get_coins_from_index(unsigned char *);
struct index_entry *get_coins_from_index_by_prefix(unsigned char *);
struct index_entry *get_coins_from_trade_index(unsigned char *);

int load_coins_from_trade_index(uint8_t, uint8_t, struct index_entry **);

#define SALE_TYPE_CC 0x0
#define SALE_TYPE_BTC 0x1
#define SALE_TYPE_XMR 0x2

int is_good_trade_coin_type(uint8_t);
uint64_t calc_coins_in_trade_locker(struct index_entry *);
struct index_entry *get_entry_from_trade_index(uint8_t, uint64_t, uint32_t);

#endif // _LOCKER_H
