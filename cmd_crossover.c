/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_crossover.c
#   Last Modified : 2025-07-29 12:10
#   Describe      : Crossover commands for handling crypto transactions.
#
#
# ====================================================*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "db.h"
#include "config.h"
#include "utils.h"
#include "crossover.h"

extern struct config_s config;

/*
 * Reserves a locker for an upcoming crypto transaction
 */
void cmd_reserve_locker(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  char *locker_key, *currency_code, *sender_address, *receipt_id, *memo;
  int rv;
  int memo_length, address_size;
  uint64_t amount;

  debug("CMD Reserve locker");

  // 16CH+16LK+3CD+8AMOUNT+1ASZ+32SENDER_ADDRESS+16ID+1ME (at least) + 2EOF
  if (ci->body_size < 95)
  {
    error("Invalid command length: %d. Expected at least 95", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  locker_key = (char *)&payload[0];
  currency_code = (char *)&payload[16];
  amount = *((uint64_t *)&payload[19]);
  amount = swap_uint64(amount);

  address_size = (int)payload[27];
  debug("Address size %d", address_size);

  if (address_size < 26 || address_size > 62)
  {
    error("Invalid address size %d", address_size);
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  sender_address = (char *)&payload[28];
  receipt_id = (char *)&payload[28 + address_size];
  memo = (char *)&payload[28 + 16 + address_size];

  // 16CH+16LK+3CD+8AMOUNT+1ASZ+address_size+16ID  -2EOF
  memo_length = ci->body_size - 16 - 16 - 3 - 8 - 1 - address_size - 16 - 2;
  if (memo_length > MAX_MEMO_SIZE)
  {
    memo_length = MAX_MEMO_SIZE;
  }

  debug("Memo length %d", memo_length);

  rv = add_crossover_index_entry(locker_key, currency_code, amount, sender_address, address_size, (unsigned char *)receipt_id, memo, memo_length);
  if (rv == -1)
  {
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }
  else if (rv == -2)
  {
    ci->command_status = ERROR_CROSSOVER_FULL;
    return;
  }

  ci->command_status = (char)STATUS_SUCCESS;

  debug("CMD Reserve locker finished");
}

/*
 * Checks RAIDA depository wallet for a crypto transaction
 */
void cmd_check_depository(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  char *locker_key, *currency_code, *transaction_id, *receipt_id, *memo;
  int rv;
  int memo_length;

  debug("CMD Check Depository");

  // 16CH+16LK+3CD+32TransactionID+16ReceiptID+1Memo (at least) + 2EOF
  if (ci->body_size < 86)
  {
    error("Invalid command length: %d. Expected at least 86", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  memo_length = ci->body_size - 85;
  if (memo_length > MAX_MEMO_SIZE)
  {
    memo_length = MAX_MEMO_SIZE;
  }

  locker_key = (char *)&payload[0];
  currency_code = (char *)&payload[16];
  transaction_id = (char *)&payload[19];
  receipt_id = (char *)&payload[51];
  memo = (char *)&payload[67];

  rv = check_depository(locker_key, currency_code, (unsigned char *)transaction_id, (unsigned char *)receipt_id, memo, memo_length);
  if (rv != 0)
  {
    ci->command_status = rv;
    return;
  }

  ci->command_status = (char)STATUS_SUCCESS;

  debug("CMD Check Depository finished");
}

/*
 * Withdraws crypto from the depository and sends it to the user
 */
void cmd_withdraw_from_depository(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  char *locker_key, *currency_code, *target_address, *receipt_id, *memo;
  int rv;
  int memo_length;
  int address_size;
  uint64_t conversion_cost;

  debug("CMD Withdraw From Depository");

  // 16CH+16LK+3CD+8AMOUNT+1AS+26ADDR+16Receipt+1MEMO + 2EOF
  if (ci->body_size < 88)
  {
    error("Invalid command length: %d. Expected at least 88", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  locker_key = (char *)&payload[0];
  currency_code = (char *)&payload[16];
  conversion_cost = *((uint64_t *)&payload[19]);
  conversion_cost = swap_uint64(conversion_cost);

  address_size = (int)payload[27];

  target_address = (char *)&payload[28];
  receipt_id = (char *)&payload[28 + address_size];
  memo = (char *)&payload[28 + address_size + 16];

  memo_length = ci->body_size - 16 - 16 - 3 - 8 - 1 - address_size - 16 - 2;
  if (memo_length > MAX_MEMO_SIZE)
  {
    memo_length = MAX_MEMO_SIZE;
  }

  // Corrected the order of arguments in the function call to match crossover.h
  rv = withdraw_from_depository(locker_key, currency_code, conversion_cost, target_address, address_size, (unsigned char *)receipt_id, memo, memo_length);
  if (rv != 0)
  {
    ci->command_status = rv;
    return;
  }

  ci->command_status = (char)STATUS_SUCCESS;

  debug("CMD Withdraw From depository Finished");
}

/*
 * Gets an exchange rate from the Proxy
 */
void cmd_get_exchange_rate(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  char *currency_code;
  long long int er, ers;
  int rv;

  debug("CMD Get Exchange Rate");

  // 16CH + 3CD + 2EOF
  if (ci->body_size != 21)
  {
    error("Invalid command length: %d. Expected 21", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  currency_code = (char *)&payload[0];

  rv = get_exchange_rate(currency_code, &er);
  if (rv != 0)
  {
    error("Failed to get rate");
    ci->command_status = rv;
    return;
  }

  ci->output_size = 8;
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  ers = swap_uint64(er);
  debug("rate %llu %llu %llx %llx", er, ers, er, ers);
  memcpy(ci->output, (unsigned char *)&ers, 8);
  ci->command_status = (char)STATUS_SUCCESS;

  debug("CMD Get Exchange Rate Finished");
}
