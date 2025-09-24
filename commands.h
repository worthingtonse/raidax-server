/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : commands.h
#   Last Modified : 2025-01-18 10:00
#   Describe      :
#
# ====================================================*/

#ifndef _COMMANDS_H
#define _COMMANDS_H

#include "protocol.h"

// Status
void cmd_echo(conn_info_t *);
void cmd_version(conn_info_t *);
void cmd_audit(conn_info_t *);
void cmd_show_stats(conn_info_t *);

// Auth
void cmd_detect(conn_info_t *);
void cmd_detect_sum(conn_info_t *);
void cmd_pown(conn_info_t *);
void cmd_pown_sum(conn_info_t *);

// Healing
void cmd_get_ticket(conn_info_t *);
void cmd_validate_ticket(conn_info_t *);
void cmd_find(conn_info_t *);
void cmd_fix(conn_info_t *);

void *send_validate_ticket_job(void *);

// Executive
void cmd_get_available_sns(conn_info_t *);
void cmd_create_coins(conn_info_t *);
void cmd_delete_coins(conn_info_t *);
void cmd_free_coins(conn_info_t *);
void cmd_get_all_sns(conn_info_t *);

// Key exchange
void cmd_encrypt_key(conn_info_t *);
void cmd_post_key(conn_info_t *);
int load_my_enc_coin(uint8_t, uint32_t, unsigned char *);
void cmd_chat_get_key(conn_info_t *);
void cmd_chat_post_key(conn_info_t *);
void cmd_get_key(conn_info_t *);
void cmd_post_key(conn_info_t *);
void cmd_key_alert(conn_info_t *);
void cmd_decrypt_raida_key(conn_info_t *);

// Locker
void cmd_store_sum(conn_info_t *);
void cmd_store_multiple_sum(conn_info_t *);
void cmd_peek(conn_info_t *);
void cmd_remove(conn_info_t *);
void cmd_put_for_sale(conn_info_t *);
void cmd_list_lockers_for_sale(conn_info_t *);
void cmd_buy(conn_info_t *);
void cmd_remove_trade_locker(conn_info_t *);
void cmd_peek_trade_locker(conn_info_t *);

// Change
void cmd_get_available_change_sns(conn_info_t *);
void cmd_break(conn_info_t *);
void cmd_join(conn_info_t *);

// Shards
void cmd_switch_shard_sum(conn_info_t *);
void cmd_pickup_coins(conn_info_t *);
void cmd_get_sns(conn_info_t *);
void cmd_rollback_switch_shard(conn_info_t *);
void cmd_switch_shard_sum_with_sns(conn_info_t *);

// Crossover
void cmd_reserve_locker(conn_info_t *);
void cmd_check_depository(conn_info_t *);
void cmd_withdraw_from_depository(conn_info_t *);
void cmd_trigger_transaction(conn_info_t *);
void cmd_get_exchange_rate(conn_info_t *);

// RPC
void cmd_nslookup(conn_info_t *);

// Filesystem
void cmd_put_object(conn_info_t *);
void cmd_get_object(conn_info_t *);
void cmd_rm_object(conn_info_t *);
char *get_crypto_key(char *, int *);

// Integrity
void cmd_get_merkle_branch(conn_info_t *);
void cmd_get_all_roots(conn_info_t *);
void cmd_get_page_data(conn_info_t *);

typedef struct
{
  coin_t coin;
  uint32_t cnt;
} coin_counter_t;

struct validate_ticket_arg_t
{
  int8_t raida_idx;
  uint32_t ticket;
  conn_info_t *ci;

  coin_t *rv_coins;
  uint32_t rv_num_coins;
};

#endif // _COMMANDS_H
