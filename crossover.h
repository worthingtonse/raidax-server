/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : crossover.h
#   Last Modified : 2025-07-29 12:05
#   Describe      : Locker header file
#                 ** FIXED function prototype mismatch. **
#
# ====================================================*/

#ifndef _CROSSOVER_H
#define _CROSSOVER_H

#include <time.h>
#include "commands.h"

// Maximum records that the index can keep
#define MAX_CROSSOVER_RECORDS 1000

// How often we clean the database
#define CROSSOVER_HOUSEKEEPING_PERIOD 4200

// How long we wait for a transaction
#define CROSSOVER_EXPIRY 3600

// Maximum memo length
#define MAX_MEMO_SIZE 1300

// Maximum number of records in the pending transactions
#define MAX_PENDING_TRANSACTIONS 32

#define CMD_PROXY_SEND_TRANSACTION 113
#define CMD_PROXY_GET_RATE 114
#define CMD_PROXY_WATCH_FOR_TRANSACTION 115

int init_crossover_index(void);
void *crossover_thread(void *);

void housekeeping_crossover_index(void);
int add_crossover_index_entry(char *, char *, uint64_t, char *, int, unsigned char *, char *, int);
int check_depository(char *, char *, unsigned char *, unsigned char *, char *, int);
int withdraw_from_depository(char *, char *, uint64_t, char *, int, unsigned char *, char *, int);
int get_exchange_rate(char *, long long int *);

struct crossover_index_entry
{
  char locker_key[16];
  char currency_code[3];
  uint64_t amount;
  char sender_address[32];
  char receipt_id[16];
  char memo[MAX_MEMO_SIZE + 1];
  time_t first_seen;
  int completed;
  int address_size;
  uint64_t confirmations;
};

struct crossover_index_entry *get_crossover_index_entry(char *);
char *proxy_request(int, char *, int, int *, uint8_t *);

#endif // _CROSSOVER_H
