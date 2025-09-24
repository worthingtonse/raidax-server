/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : protocol.c
#   Last Modified : 2025-12-20
#   Describe      : RAIDA X protocol related functions.
#                   Added software AES fallback for 256-bit encryption
#
#
# ====================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#include "protocol.h"
#include "commands.h"
#include "log.h"
#include "net.h"
#include "config.h"
#include "utils.h"
#include "db.h"
#include "aes.h"
#include "locker.h"
#include "iaesni.h"

// External globals
extern struct config_s config;
extern int aes_hw;

// File-static data
static struct ticket_entry_t tickets[TICKET_POOL_SIZE];
// A hash table for instant lookups of active tickets.
// The key is the ticket ID, the value is a pointer to the entry in the `tickets` array.
#define TICKET_HASH_TABLE_SIZE (TICKET_POOL_SIZE * 2) // Larger size reduces collisions
static struct ticket_entry_t *ticket_hash_table[TICKET_HASH_TABLE_SIZE];
// A stack (free list) holding the indices of available slots in the `tickets` array.
static int ticket_free_stack[TICKET_POOL_SIZE];
static int ticket_free_stack_top;

// Granular mutexes for thread-safe access to the new data structures.
static pthread_mutex_t ticket_ht_mtx; // Protects the hash table
static pthread_mutex_t ticket_fs_mtx; // Protects the free stack

// Software AES-256-CTR implementation
static int software_aes_256_ctr(unsigned char *in, unsigned char *out, unsigned char *key, int len, unsigned char *iv)
{
  EVP_CIPHER_CTX *ctx;
  int outlen, tmplen;
  unsigned char temp_iv[16];

  // AES-256 uses first 16 bytes of the 24-byte nonce as IV
  memcpy(temp_iv, iv, 16);

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    error("Failed to create EVP cipher context");
    return -1;
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, temp_iv) != 1)
  {
    error("Failed to initialize AES-256-CTR");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  if (EVP_EncryptUpdate(ctx, out, &outlen, in, len) != 1)
  {
    error("Failed to encrypt/decrypt data");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  if (EVP_EncryptFinal_ex(ctx, out + outlen, &tmplen) != 1)
  {
    error("Failed to finalize encryption/decryption");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

// Command dispatch table
command_handler_t *commands[MAX_COMMAND_GROUP + 1][MAX_COMMAND + 1] = {
    // Status = 0
    {
        [0] = cmd_echo,
        [1] = cmd_version,
        [2] = cmd_show_stats,
        [3] = cmd_audit,
    },
    // Auth = 1
    {
        [10] = cmd_detect,
        [11] = cmd_detect_sum,
        [20] = cmd_pown,
        [21] = cmd_pown_sum,
    },
    // Healing = 2
    {
        [40] = cmd_get_ticket,
        [50] = cmd_validate_ticket,
        [60] = cmd_find,
        [80] = cmd_fix,
    },
    // Executive = 3
    {
        [120] = cmd_get_available_sns,
        [130] = cmd_create_coins,
        [140] = cmd_delete_coins,
        [150] = cmd_free_coins,
        [160] = cmd_get_all_sns,
    },
    // Key Exchange = 4
    {
        [41] = cmd_post_key,
        [42] = cmd_key_alert,
        [43] = cmd_get_key,
        [44] = cmd_encrypt_key,
        [45] = cmd_decrypt_raida_key,
    },
    // Banking = 5
    {},
    // Chat = 6
    {},
    // BlockChain = 7
    {},
    // Locker = 8
    {
        [81] = cmd_peek_trade_locker,
        [82] = cmd_store_sum,
        [83] = cmd_peek,
        [84] = cmd_remove,
        [85] = cmd_put_for_sale,
        [86] = cmd_list_lockers_for_sale,
        [87] = cmd_buy,
        [88] = cmd_store_multiple_sum,
        [89] = cmd_remove_trade_locker,
    },
    // Change = 9
    {
        [91] = cmd_get_available_change_sns,
        [92] = cmd_break,
        [93] = cmd_join,
    },
    // Shard = 10
    {
        [170] = cmd_switch_shard_sum,
        [171] = cmd_pickup_coins,
        [172] = cmd_get_sns,
        [173] = cmd_rollback_switch_shard,
        [174] = cmd_switch_shard_sum_with_sns,
    },
    // Crossover = 11
    {
        [110] = cmd_reserve_locker,
        [111] = cmd_check_depository,
        [112] = cmd_withdraw_from_depository,
        [114] = cmd_get_exchange_rate,
    },
    // RPC = 12
    {
        [120] = cmd_nslookup,
    },
    // FileSystem = 13
    {
        [134] = cmd_put_object,
        [135] = cmd_get_object,
        [136] = cmd_rm_object,
    },
    // Integrity = 14
    {
        [2] = cmd_get_merkle_branch,
        [4] = cmd_get_page_data,
        [5] = cmd_get_all_roots,
    },
    // RKE = 15
    // {
    //     [CMD_RKE_PRELOAD_MASTER_KEY] = cmd_rke_preload_master_key,
    //     [CMD_RKE_GET_KEY_SHARE] = cmd_rke_get_key_share,
    //     [CMD_RKE_LIST_CS] = cmd_rke_list_cs,
    //     [CMD_RKE_REGISTER_AS_CS] = cmd_rke_register_as_cs,
    //     [CMD_RKE_TEST_GET_KEY_AND_ENCRYPT] = cmd_rke_test_get_key_and_encrypt,
    //     [CMD_RKE_TEST_DECRYPT] = cmd_rke_test_decrypt,
    // },
};
// helper function
int get_response_header_size_for_encryption_type(int encryption_type)
{
  if (encryption_type == ENCRYPTION_TYPE_NONE ||
      encryption_type == ENCRYPTION_TYPE_AES ||
      encryption_type == ENCRYPTION_TYPE_LOCKER)
  {
    return 32; // Legacy response header
  }
  else
  {
    return 48; // Modern response header
  }
}

void write_stat(conn_info_t *ci)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  unsigned long tm_diff = (tv.tv_sec - ci->start_time.tv_sec) * 1000000 + (tv.tv_usec - ci->start_time.tv_usec);
  ci->exec_time = tm_diff;

  unsigned long tm = ci->start_time.tv_sec * 1000000 + ci->start_time.tv_usec;
  debug("<STAT> date:%lu ip:%s user:%u/%u command:%u/%u exec_time:%lu status:%u",
        tm, ci->ip, ci->encryption_denomination, ci->encryption_sn, ci->cgroup, ci->command, ci->exec_time, ci->command_status);
}

void send_command_error(int code, conn_info_t *ci)
{
  ci->command_status = code;
  ci->output_size = 0;
  if (ci->output)
  {
    free(ci->output);
    ci->output = NULL;
  }
  prepare_response(ci);
}

void run_command(void *arg)
{
  conn_info_t *ci = (conn_info_t *)arg;
  if (!ci)
  {
    error("Internal error. CI is NULL in run_command");
    return;
  }

  command_handler_t *command_handler = NULL;
  if (ci->cgroup <= MAX_COMMAND_GROUP && ci->command <= MAX_COMMAND)
  {
    command_handler = commands[ci->cgroup][ci->command];
  }

  if (command_handler == NULL)
  {
    error("Command %d/%d not found", ci->cgroup, ci->command);
    send_command_error(ERROR_INVALID_COMMAND, ci);
    return;
  }

  debug("Client %s, Running command %d/%d", ci->ip, ci->cgroup, ci->command);
  command_handler(ci);
  prepare_response(ci);
}

void prepare_response(conn_info_t *ci)
{
  // This is the size of the actual data payload from the command handler
  int payload_size = ci->output_size;
  int hmac_size = 0;

  // Determine if we need to add an HMAC based on the original request's encryption type
  if (ci->encryption_type == ENCRYPTION_TYPE_AES_256_SINGLE_KEY ||
      ci->encryption_type == ENCRYPTION_TYPE_AES_256_DOUBLE_KEY)
  {
    hmac_size = 32;
  }

  // Calculate the total size of the response body (payload + hmac (if any) + trailer)
  int final_body_size = (payload_size > 0) ? (payload_size + hmac_size + 2) : 0;
  int header_size = get_response_header_size_for_encryption_type(ci->encryption_type);
  int blen = header_size + final_body_size;

  ci->write_buf = malloc(blen);
  if (!ci->write_buf)
  {
    error("Failed to allocate memory for response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    if (ci->sa == NULL)
    {
      write_stat(ci);
      close_connection(ci);
    }
    else
    {
      finish_command(ci);
    }
    return;
  }

  // Generate the header. We pass `final_body_size` so the header's length field is correct.
  ci->output_size = final_body_size;
  get_response_header((char *)ci->write_buf, ci->command_status, ci->cgroup, ci);

  // Restore original payload size for internal logic
  ci->output_size = payload_size;

  // If there is a body to send (payload exists)
  if (final_body_size > 0 && ci->output)
  {
    // Pointer to where the body will start in the final response buffer
    unsigned char *body_start = ci->write_buf + header_size;

    // ======== MODERN CLIENT PATH (Types 4 & 5) ========
    if (ci->encryption_type == ENCRYPTION_TYPE_AES_256_SINGLE_KEY ||
        ci->encryption_type == ENCRYPTION_TYPE_AES_256_DOUBLE_KEY)
    {
      // 1. Encrypt the payload (in-place in the ci->output buffer)
      if (aes_hw)
      {
        intel_AES_encdec256_CTR(ci->output, ci->output, ci->encryption_an_256,
                                (payload_size + 15) / 16, ci->response_nonce);
      }
      else
      {
        if (software_aes_256_ctr(ci->output, ci->output, ci->encryption_an_256,
                                 payload_size, ci->response_nonce) != 0)
        {
          error("Software AES-256 encryption failed");
          ci->command_status = ERROR_INTERNAL;
        }
      }

      // 2. Copy the now-encrypted payload into the final response buffer
      memcpy(body_start, ci->output, payload_size);

      // 3. Compute the HMAC on the ciphertext and place it right after the ciphertext
      unsigned char *hmac_start = body_start + payload_size;
      compute_hmac(body_start, payload_size, ci->encryption_an_256, hmac_start);
    }
    // ======== LEGACY CLIENT PATH (Types 0, 1, 2) ========
    else
    {
      // 1. For encrypted types (1 & 2), encrypt the payload in-place first.
      if (ci->encryption_type == ENCRYPTION_TYPE_AES || ci->encryption_type == ENCRYPTION_TYPE_LOCKER)
      {
        if (aes_hw)
        {
          // ** RESTORED: This is the original logic and calculation **
          int num_blocks = (final_body_size - 2 + 15) / 16;
          intel_AES_encdec128_CTR(ci->output, ci->output, ci->encryption_an,
                                  num_blocks, ci->nonce);
        }
        else
        {
          crypt_ctr(ci->encryption_an, ci->output, final_body_size - 2, ci->nonce);
        }
      }

      // 2. For all legacy types (0, 1, 2), copy the payload into the final buffer.
      //    For type 0, this is plaintext. For types 1 & 2, it is now ciphertext.
      memcpy(body_start, ci->output, final_body_size - 2);
    }

    // Add the final ">>" trailer to the very end of the response body for ALL types.
    ci->write_buf[blen - 2] = 0x3e;
    ci->write_buf[blen - 1] = 0x3e;
  }

  // Send the fully constructed response
  if (ci->sa != NULL)
  {
    // UDP
    sendto(ci->sk, ci->write_buf, blen, 0, ci->sa, sizeof(struct sockaddr_in));
    write_stat(ci);
    finish_command(ci);
  }
  else
  {
    // TCP
    ci->bytes_to_write = blen;
    ci->bytes_written = 0;
    ci->state = STATE_WANT_WRITE;
    arm_socket_for_write(ci);
  }
}

void finish_command(conn_info_t *ci)
{
  if (ci->sa == NULL)
  {
    debug("Finished processing for fd %d", ci->sk);
  }
  else
  {
    free_ci(ci);
  }
}

int validate_header(unsigned char *buf, conn_info_t *ci)
{
  uint8_t cg, command_idx;
  uint16_t coin_id;
  struct page_s *page;
  int sn_idx;
  struct index_entry *ie;
  uint8_t shard_id;

  debug("Validating header for client %s", ci->ip);

  // Standard validation (same for all types)
  if (buf[0] != 1)
    return ERROR_INVALID_ROUTING;
  if (buf[1] != 0)
    return ERROR_INVALID_SPLIT_ID;
  if (buf[2] != config.raida_no)
    return ERROR_INVALID_RAIDA_ID;

  cg = buf[4];
  if (cg < 0 || cg > MAX_COMMAND_GROUP)
    return ERROR_INVALID_COMMAND_GROUP;

  shard_id = buf[3];
  if (shard_id < 0 || shard_id > MAX_SHARD)
    return ERROR_INVALID_SHARD_ID;

  command_idx = buf[5];
  if (command_idx < 0 || command_idx > MAX_COMMAND)
    return ERROR_INVALID_COMMAND;

  if (commands[cg][command_idx] == NULL)
    return ERROR_INVALID_COMMAND;

  ci->shard_id = shard_id;
  ci->cgroup = cg;
  ci->command = command_idx;

  coin_id = (buf[6] << 8) | buf[7];
  if (coin_id != config.coin_id)
    return ERROR_INVALID_COIN_ID;

  ci->coin_id = coin_id;
  ci->encryption_type = buf[16];

  // Handle encryption type validation and nonce extraction based on type
  if (ci->encryption_type == ENCRYPTION_TYPE_NONE)
  {
    // Type 0: Legacy unencrypted - EXACTLY like old code
    ci->body_size = (buf[22] << 8) | buf[23];
    ci->e0 = buf[30]; // Legacy echo bytes location
    ci->e1 = buf[31];
    memset(ci->nonce, 0, 16); // Zero all 16 bytes like old code
    ci->encryption_denomination = 0;
    ci->encryption_sn = 0;
    ci->encryption_denomination2 = 0;
    ci->encryption_sn2 = 0;
    memset(ci->encryption_an, 0, 32);
    return NO_ERROR;
  }
  else if (ci->encryption_type == ENCRYPTION_TYPE_AES ||
           ci->encryption_type == ENCRYPTION_TYPE_LOCKER)
  {
    // Type 1 and 2: Legacy 32-byte header behavior - EXACTLY like old code
    ci->body_size = (buf[22] << 8) | buf[23];
    ci->e0 = buf[30]; // Legacy echo bytes location
    ci->e1 = buf[31];

    ci->encryption_denomination = (int8_t)buf[17];
    ci->encryption_sn = get_sn(&buf[18]);

    // Clear second coin fields for Type 1/2
    ci->encryption_denomination2 = 0;
    ci->encryption_sn2 = 0;

    // Initialize nonce buffer to all zeros first (like old code)
    memset(ci->nonce, 0, 16);

    debug("Legacy encrypted with %hhx:%d", ci->encryption_denomination, ci->encryption_sn);

    // Validate denomination and get AN based on type
    if (ci->encryption_type == ENCRYPTION_TYPE_LOCKER)
    {
      ie = get_coins_from_index_by_prefix(&buf[17]);
      if (ie == NULL)
        return ERROR_INVALID_ENCRYPTION;
      memcpy(ci->encryption_an, ie->an, 16);
    }
    else
    {
      // Type 1: AES
      page = get_page_by_sn_lock(ci->encryption_denomination, ci->encryption_sn);
      if (page == NULL)
        return ERROR_INVALID_ENCRYPTION;
      sn_idx = ci->encryption_sn % RECORDS_PER_PAGE;
      memcpy(ci->encryption_an, &page->data[sn_idx * 17], 16);
      unlock_page(page);
    }

    // CRITICAL: Both AES and LOCKER types get 8-byte nonce (like old code)
    memcpy(ci->nonce, &buf[24], 8);
    // Remaining 8 bytes stay zero from memset above
  }
  else if (ci->encryption_type == ENCRYPTION_TYPE_AES_256_SINGLE_KEY)
  {
    // Type 4: Single coin, hashed to 256-bit
    ci->body_size = (buf[17] << 8) | buf[18]; // Specification bytes 17-18

    // No echo bytes defined in specification for modern types

    memcpy(ci->request_nonce, &buf[24], 24); // Full 24-byte nonce

    ci->encryption_denomination = (int8_t)buf[19]; // Specification byte 19
    ci->encryption_sn = get_u32(&buf[20]);         // Specification bytes 20-23

    // Clear second coin fields for Type 4
    ci->encryption_denomination2 = 0;
    ci->encryption_sn2 = 0;

    struct page_s *page = get_page_by_sn_lock(ci->encryption_denomination, ci->encryption_sn);
    if (!page)
      return ERROR_ENCRYPTION_COIN_NOT_FOUND;
    unsigned char first_an[16];
    memcpy(first_an, &page->data[(ci->encryption_sn % RECORDS_PER_PAGE) * 17], 16);
    unlock_page(page);

    // Hash single AN to get 32-byte key
    generate_an_hash(first_an, 16, ci->encryption_an_256);
  }
  else if (ci->encryption_type == ENCRYPTION_TYPE_AES_256_DOUBLE_KEY)
  {
    // Type 5: Two coins, concatenate+hash to 256-bit
    ci->body_size = (buf[17] << 8) | buf[18]; //  bytes 17-18

    // No echo bytes defined in specification for modern types

    // FIRST COIN: From encryption section (bytes 19-23)
    ci->encryption_denomination = (int8_t)buf[19]; //  byte 19
    ci->encryption_sn = get_u32(&buf[20]);         //  bytes 20-23

    // SECOND COIN: From dual-purpose nonce section (bytes 24-28 )
    ci->encryption_denomination2 = (int8_t)buf[24];
    ci->encryption_sn2 = get_u32(&buf[25]);

    // DUAL-PURPOSE NONCE: Full 24 bytes (including the coin info bytes)
    memcpy(ci->request_nonce, &buf[24], 24);

    debug("Type 5: First coin Den=%d SN=%u, Second coin Den=%d SN=%u",
          ci->encryption_denomination, ci->encryption_sn,
          ci->encryption_denomination2, ci->encryption_sn2);

    // Get both coins' ANs and concatenate
    struct page_s *page1 = get_page_by_sn_lock(ci->encryption_denomination, ci->encryption_sn);
    if (!page1)
      return ERROR_ENCRYPTION_COIN_NOT_FOUND;
    unsigned char first_an[16];
    memcpy(first_an, &page1->data[(ci->encryption_sn % RECORDS_PER_PAGE) * 17], 16);
    unlock_page(page1);

    struct page_s *page2 = get_page_by_sn_lock(ci->encryption_denomination2, ci->encryption_sn2);
    if (!page2)
      return ERROR_ENCRYPTION_COIN_NOT_FOUND;
    unsigned char second_an[16];
    memcpy(second_an, &page2->data[(ci->encryption_sn2 % RECORDS_PER_PAGE) * 17], 16);
    unlock_page(page2);

    // Concatenate both 16-byte ANs, then hash to get 32-byte key
    unsigned char combined_an[32];
    memcpy(combined_an, first_an, 16);
    memcpy(combined_an + 16, second_an, 16);
    generate_an_hash(combined_an, 32, ci->encryption_an_256);
  }
  else
  {
    return ERROR_INVALID_ENCRYPTION_CODE;
  }

  return NO_ERROR;
}
int validate_decrypt_body(conn_info_t *ci)
{
  debug("Validating body for encryption type %d", ci->encryption_type);

  if (ci->body_size < 2)
    return ERROR_INVALID_PACKET_LENGTH;
  if (ci->body[ci->body_size - 2] != 0x3e || ci->body[ci->body_size - 1] != 0x3e)
    return ERROR_INVALID_EOF;

  if (ci->encryption_type == ENCRYPTION_TYPE_NONE)
  {
    // Type 0: Unencrypted. The challenge is a direct copy.
    if (ci->body_size < 18)
      return ERROR_INVALID_PACKET_LENGTH;

    memcpy(ci->challenge_hash, ci->body, 16); //  Direct copy for unencrypted

    uint32_t crc = crc32b(ci->body, 12);
    int b0 = (crc >> 24) & 0xff;
    int b1 = (crc >> 16) & 0xff;
    int b2 = (crc >> 8) & 0xff;
    int b3 = crc & 0xff;

    if (b0 != ci->body[12] || b1 != ci->body[13] || b2 != ci->body[14] || b3 != ci->body[15])
    {
      debug("%x %x %x %x vs %x %x %x %x", b0, b1, b2, b3, ci->body[12], ci->body[13], ci->body[14], ci->body[15]);
      return ERROR_INVALID_CRC;
    }
  }
  else if (ci->encryption_type == ENCRYPTION_TYPE_AES ||
           ci->encryption_type == ENCRYPTION_TYPE_LOCKER)
  {
    // Type 1 and 2: Legacy encrypted. Decrypt first, then XOR for the hash.
    if (aes_hw)
    {
      debug("Using hardware AES-128 for Type %d body decryption", ci->encryption_type);
      int num_blocks = (ci->body_size - 2 + 15) / 16;
      intel_AES_encdec128_CTR(ci->body, ci->body, ci->encryption_an, num_blocks, ci->nonce);
    }
    else
    {
      debug("Using software AES-128 for Type %d body decryption", ci->encryption_type);
      crypt_ctr(ci->encryption_an, ci->body, ci->body_size - 2, ci->nonce);
    }

    if (ci->body_size < 18)
      return ERROR_INVALID_PACKET_LENGTH;

    // CORRECT: Create the final challenge hash by XORing the decrypted data with the key
    for (int i = 0; i < 16; i++)
    {
      ci->challenge_hash[i] = ci->body[i] ^ ci->encryption_an[i];
    }

    uint32_t crc = crc32b(ci->body, 12);
    int b0 = (crc >> 24) & 0xff;
    int b1 = (crc >> 16) & 0xff;
    int b2 = (crc >> 8) & 0xff;
    int b3 = crc & 0xff;

    if (b0 != ci->body[12] || b1 != ci->body[13] || b2 != ci->body[14] || b3 != ci->body[15])
    {
      debug("%x %x %x %x vs %x %x %x %x", b0, b1, b2, b3, ci->body[12], ci->body[13], ci->body[14], ci->body[15]);
      return ERROR_INVALID_CRC;
    }
  }
  else if (ci->encryption_type == ENCRYPTION_TYPE_AES_256_SINGLE_KEY ||
           ci->encryption_type == ENCRYPTION_TYPE_AES_256_DOUBLE_KEY)
  {
    //  NEW: HMAC verification for modern encryption
    if (ci->body_size < 34) // 32 bytes for HMAC + 2 for trailer
      return ERROR_INVALID_PACKET_LENGTH;

    int ciphertext_len = ci->body_size - 2 - 32;
    unsigned char *ciphertext = ci->body;
    unsigned char *received_hmac = ci->body + ciphertext_len;

    unsigned char calculated_hmac[32];
    compute_hmac(ciphertext, ciphertext_len, ci->encryption_an_256, calculated_hmac);

    if (memcmp(received_hmac, calculated_hmac, 32) != 0)
    {
      error("HMAC verification failed for type %d", ci->encryption_type);
      return ERROR_INVALID_HMAC;
    }

    debug("HMAC verification successful for type %d", ci->encryption_type);

    // Type 4 and 5: Modern encrypted - No challenge/CRC validation needed
    if (aes_hw)
    {
      debug("Using hardware AES-256 for Type %d body decryption", ci->encryption_type);
      intel_AES_encdec256_CTR(ci->body, ci->body, ci->encryption_an_256,
                              (ci->body_size - 2 + 15) / 16, ci->request_nonce);
    }
    else
    {
      debug("Using software AES-256 fallback for Type %d body decryption", ci->encryption_type);
      if (software_aes_256_ctr(ci->body, ci->body, ci->encryption_an_256,
                               ci->body_size - 2, ci->request_nonce) != 0)
      {
        error("Software AES-256 decryption failed");
        return ERROR_INTERNAL;
      }
    }
    debug("Type %d decryption completed", ci->encryption_type);
  }
  else
  {
    return ERROR_INVALID_ENCRYPTION_CODE;
  }

  return NO_ERROR;
}

void get_response_header(char *response, int status, int cg, conn_info_t *ci)
{
  struct timeval tv;
  unsigned long tm;

  gettimeofday(&tv, NULL);
  tm = (tv.tv_sec - ci->start_time.tv_sec) * 1000000 + (tv.tv_usec - ci->start_time.tv_usec);
  ci->exec_time = tm;

  if (ci->encryption_type == ENCRYPTION_TYPE_NONE ||
      ci->encryption_type == ENCRYPTION_TYPE_AES ||
      ci->encryption_type == ENCRYPTION_TYPE_LOCKER)
  {
    // LEGACY PATH - Type 0, 1 and 2: 32-byte header format (EXACTLY like old code)
    memset(response, 0, 32);

    response[0] = config.raida_no; // RAIDA ID
    response[1] = 0;               // Shard ID = 0 for legacy
    response[2] = status;          // Response Status
    response[3] = cg;              // Command Group
    response[4] = 0;               // UDP Count high
    response[5] = 1;               // UDP Count low (always 1)
    response[6] = ci->e0;          // Echo bytes (from legacy location)
    response[7] = ci->e1;
    response[8] = 0; // Reserved

    // Size (3 bytes) - big endian
    response[9] = (ci->output_size >> 16) & 0xff;
    response[10] = (ci->output_size >> 8) & 0xff;
    response[11] = ci->output_size & 0xff;

    // Execution time (4 bytes) - big endian
    response[12] = (tm >> 24) & 0xff;
    response[13] = (tm >> 16) & 0xff;
    response[14] = (tm >> 8) & 0xff;
    response[15] = tm & 0xff;

    // Challenge hash (16 bytes)

    memcpy(&response[16], ci->challenge_hash, 16);
  }
  else
  {
    // MODERN PATH - Type 4 and 5: 48-byte header format
    memset(response, 0, 48);

    // Routing Section (bytes 0-7)
    response[0] = config.raida_no; // RAIDA ID
    response[1] = 0;               // Shard ID
    response[2] = status;          // Response Status
    response[3] = cg;              // Command Group

    // Presentation Section (bytes 4-15)
    put_u32(tm, (unsigned char *)&response[4]); // Execution time in bytes 4-7
    response[8] = 0;                            // Bitfield

    // Size in bytes 9-11 (matching request format)
    response[9] = (ci->output_size >> 16) & 0xff;
    response[10] = (ci->output_size >> 8) & 0xff;
    response[11] = ci->output_size & 0xff;

    // Optional: Echo client's fragmentation info
    // response[14] = ci->packet_index;  // From request
    // response[15] = ci->array_length;  // From request

    // Encryption ID Section (bytes 16-23)
    response[16] = ci->encryption_type; // Echo encryption type

    if (ci->encryption_type != ENCRYPTION_TYPE_NONE)
    {
      // Echo first coin info for reference
      response[17] = ci->encryption_denomination;
      put_u32(ci->encryption_sn, (unsigned char *)&response[18]);

      // Nonce Section (bytes 24-47)
      // Generate new response nonce for response encryption
      generate_random_bytes(ci->response_nonce, 24);

      if (ci->encryption_type == ENCRYPTION_TYPE_AES_256_DOUBLE_KEY)
      {
        // Type 5: Handle dual-purpose nonce section
        response[24] = ci->encryption_denomination2;
        put_u32(ci->encryption_sn2, (unsigned char *)&response[25]);
        memcpy(&response[29], &ci->response_nonce[5], 17);
        response[46] = ci->request_nonce[22];
        response[47] = ci->request_nonce[23];
      }
      else
      {
        // Type 4: 22 bytes of response nonce, then echo
        memcpy(&response[24], ci->response_nonce, 22);
        response[46] = ci->request_nonce[22];
        response[47] = ci->request_nonce[23];
      }
    }
  }
}

unsigned char *get_body_payload(conn_info_t *ci)
{
  if (ci->encryption_type == ENCRYPTION_TYPE_NONE ||
      ci->encryption_type == ENCRYPTION_TYPE_AES ||
      ci->encryption_type == ENCRYPTION_TYPE_LOCKER)
  {
    return ci->body + 16;
  }
  return ci->body; // No skip for modern types (4, 5) - no challenge
}

// int init_ticket_storage(void)
// {
//   debug("Initializing ticket memory storage with fine-grained locking");
//   for (int i = 0; i < TICKET_POOL_SIZE; i++)
//   {
//     tickets[i].created_at = 0;
//     if (pthread_mutex_init(&tickets[i].mtx, NULL) != 0)
//     {
//       error("Failed to initialize mutex for ticket slot %d: %s", i, strerror(errno));
//       return -1;
//     }
//   }
//   return 0;
// }
int init_ticket_storage(void)
{
  debug("Initializing high-performance ticket system...");

  if (pthread_mutex_init(&ticket_ht_mtx, NULL) != 0)
  {
    error("Failed to initialize ticket hash table mutex");
    return -1;
  }
  if (pthread_mutex_init(&ticket_fs_mtx, NULL) != 0)
  {
    error("Failed to initialize ticket free stack mutex");
    // Clean up the other mutex before failing
    pthread_mutex_destroy(&ticket_ht_mtx);
    return -1;
  }

  // Initialize the main ticket array and the hash table buckets
  for (int i = 0; i < TICKET_POOL_SIZE; i++)
  {
    tickets[i].created_at = 0;
    tickets[i].next = NULL;
  }
  for (int i = 0; i < TICKET_HASH_TABLE_SIZE; i++)
  {
    ticket_hash_table[i] = NULL;
  }

  // Pre-populate the free stack with all available indices
  ticket_free_stack_top = -1;
  for (int i = 0; i < TICKET_POOL_SIZE; i++)
  {
    ticket_free_stack[++ticket_free_stack_top] = i;
  }

  debug("Ticket system initialized with %d free slots.", ticket_free_stack_top + 1);
  return 0;
}

// void check_tickets(void)
// {
//   time_t now;
//   debug("Looking for expired tickets");
//   time(&now);
//   for (int j = 0; j < TICKET_POOL_SIZE; j++)
//   {
//     if (pthread_mutex_lock(&tickets[j].mtx) != 0)
//       continue;
//     if (tickets[j].created_at != 0 && (difftime(now, tickets[j].created_at) > TICKET_RELEASE_SECONDS))
//     {
//       tickets[j].created_at = 0;
//     }
//     pthread_mutex_unlock(&tickets[j].mtx);
//   }
// }

/**
 * @brief Periodically scans for and cleans up expired tickets.
 */
void check_tickets(void)
{
  time_t now;
  time(&now);
  int cleaned_count = 0;

  debug("Checking for expired tickets...");

  for (int i = 0; i < TICKET_POOL_SIZE; i++)
  {
    if (tickets[i].created_at == 0)
    {
      continue;
    }

    if (difftime(now, tickets[i].created_at) > TICKET_RELEASE_SECONDS)
    {
      uint32_t expired_ticket = tickets[i].ticket;

      if (pthread_mutex_lock(&ticket_ht_mtx) != 0)
      {
        error("check_tickets: Failed to lock hash table mutex for ticket %x: %s",
              expired_ticket, strerror(errno));
        continue;
      }

      uint32_t hash_idx = expired_ticket % TICKET_HASH_TABLE_SIZE;
      struct ticket_entry_t *current = ticket_hash_table[hash_idx];
      struct ticket_entry_t *prev = NULL;
      int found_in_hash = 0;

      while (current != NULL)
      {
        if (current == &tickets[i])
        {
          if (prev != NULL)
          {
            prev->next = current->next;
          }
          else
          {
            ticket_hash_table[hash_idx] = current->next;
          }
          found_in_hash = 1;
          break;
        }
        prev = current;
        current = current->next;
      }

      if (pthread_mutex_unlock(&ticket_ht_mtx) != 0)
      {
        error("check_tickets: Failed to unlock hash table mutex for ticket %x: %s",
              expired_ticket, strerror(errno));
      }

      tickets[i].created_at = 0;
      tickets[i].num_coins = 0;
      tickets[i].next = NULL;
      memset(tickets[i].claims, 0, TOTAL_RAIDA_SERVERS);

      if (pthread_mutex_lock(&ticket_fs_mtx) != 0)
      {
        error("check_tickets: Failed to lock free stack mutex for slot %d: %s",
              i, strerror(errno));
        continue;
      }

      if (ticket_free_stack_top >= TICKET_POOL_SIZE - 1)
      {
        error("CRITICAL: Free stack overflow detected during cleanup. Pool corruption suspected. "
              "Current top: %d, Pool size: %d",
              ticket_free_stack_top, TICKET_POOL_SIZE);
        ticket_free_stack_top = TICKET_POOL_SIZE - 2;
      }

      ticket_free_stack[++ticket_free_stack_top] = i;
      cleaned_count++;

      if (pthread_mutex_unlock(&ticket_fs_mtx) != 0)
      {
        error("check_tickets: Failed to unlock free stack mutex for slot %d: %s",
              i, strerror(errno));
      }

      if (found_in_hash)
      {
        debug("Cleaned expired ticket %x from slot %d", expired_ticket, i);
      }
      else
      {
        error("Expired ticket %x from slot %d was not found in hash table - possible corruption",
              expired_ticket, i);
      }
    }
  }

  if (cleaned_count > 0)
  {
    debug("Cleaned up %d expired tickets. Free slots available: %d",
          cleaned_count, ticket_free_stack_top + 1);
  }
}

// struct ticket_entry_t *get_free_ticket_slot(void)
// {
//   for (int j = 0; j < TICKET_POOL_SIZE; j++)
//   {
//     if (pthread_mutex_trylock(&tickets[j].mtx) == 0)
//     {
//       if (tickets[j].created_at == 0)
//       {
//         time(&tickets[j].created_at);
//         tickets[j].num_coins = 0;
//         generate_random_bytes((unsigned char *)&tickets[j].ticket, 4);
//         memset(tickets[j].claims, 0, TOTAL_RAIDA_SERVERS);
//         return &tickets[j];
//       }
//       pthread_mutex_unlock(&tickets[j].mtx);
//     }
//   }
//   error("No free ticket slot found");
//   return NULL;
// }
/**
 * @brief Gets a free ticket slot instantly from the free stack. O(1) complexity.
 */
struct ticket_entry_t *get_free_ticket_slot(void)
{
  int slot_idx = -1;

  // Get an available index from the free stack
  if (pthread_mutex_lock(&ticket_fs_mtx) != 0)
  {
    error("get_free_ticket_slot: Failed to lock free stack mutex.");
    return NULL;
  }
  if (ticket_free_stack_top >= 0)
  {
    slot_idx = ticket_free_stack[ticket_free_stack_top--];
  }
  pthread_mutex_unlock(&ticket_fs_mtx);

  if (slot_idx == -1)
  {
    error("No free ticket slots available. The pool is exhausted.");
    return NULL;
  }
  if (slot_idx < 0 || slot_idx >= TICKET_POOL_SIZE)
  {
    error("Invalid slot index %d retrieved from free stack - pool corruption detected", slot_idx);
    return NULL;
  }

  struct ticket_entry_t *te = &tickets[slot_idx];

  // Initialize the ticket entry's data
  time(&te->created_at);
  te->num_coins = 0;
  generate_random_bytes((unsigned char *)&te->ticket, 4);
  memset(te->claims, 0, TOTAL_RAIDA_SERVERS);
  te->next = NULL;

  // Add the newly initialized ticket to the hash table for fast lookups
  if (pthread_mutex_lock(&ticket_ht_mtx) != 0)
  {
    error("get_free_ticket_slot: Failed to lock hash table mutex.");
    // We have a slot but can't add it to the hash table, so we must return it to the free stack to prevent a leak.
    pthread_mutex_lock(&ticket_fs_mtx);
    ticket_free_stack[++ticket_free_stack_top] = slot_idx;
    pthread_mutex_unlock(&ticket_fs_mtx);
    return NULL;
  }
  uint32_t hash_idx = te->ticket % TICKET_HASH_TABLE_SIZE;
  te->next = ticket_hash_table[hash_idx];
  ticket_hash_table[hash_idx] = te;
  pthread_mutex_unlock(&ticket_ht_mtx);

  debug("Allocated new ticket %x from slot #%d", te->ticket, slot_idx);
  return te;
}

// struct ticket_entry_t *get_ticket_entry(uint32_t ticket)
// {
//   for (int j = 0; j < TICKET_POOL_SIZE; j++)
//   {
//     if (pthread_mutex_lock(&tickets[j].mtx) != 0)
//       continue;
//     if (tickets[j].created_at != 0 && tickets[j].ticket == ticket)
//     {
//       return &tickets[j];
//     }
//     pthread_mutex_unlock(&tickets[j].mtx);
//   }
//   return NULL;
// }
/**
 * @brief Finds a ticket entry instantly from the hash table. O(1) average complexity.
 */
/**
 * @brief Finds a ticket entry instantly from the hash table. O(1) average complexity.
 * @param ticket The ticket ID to search for
 * @return Pointer to ticket entry if found, NULL otherwise
 */
struct ticket_entry_t *get_ticket_entry(uint32_t ticket)
{
  struct ticket_entry_t *te = NULL;

  if (pthread_mutex_lock(&ticket_ht_mtx) != 0)
  {
    error("get_ticket_entry: Failed to lock hash table mutex: %s", strerror(errno));
    return NULL;
  }

  uint32_t hash_idx = ticket % TICKET_HASH_TABLE_SIZE;
  struct ticket_entry_t *current = ticket_hash_table[hash_idx];

  while (current != NULL)
  {
    if (current->ticket == ticket && current->created_at != 0)
    {
      te = current;
      break;
    }
    current = current->next;
  }

  if (pthread_mutex_unlock(&ticket_ht_mtx) != 0)
  {
    error("get_ticket_entry: Failed to unlock hash table mutex: %s", strerror(errno));
  }

  if (te != NULL)
  {
    debug("Found ticket %x in hash table", ticket);
  }
  else
  {
    debug("Ticket %x not found in hash table", ticket);
  }

  return te;
}

// void unlock_ticket_entry(struct ticket_entry_t *te)
// {
//   if (te)
//   {
//     if (pthread_mutex_unlock(&te->mtx) != 0)
//     {
//       error("Failed to unlock ticket entry mutex.");
//     }
//   }
// }

/**
 * @brief No-op function for API compatibility.
 * With the new locking strategy, no locks are held after get_ticket_entry returns.
 * @param te Ticket entry pointer (unused but kept for API compatibility)
 */
void unlock_ticket_entry(struct ticket_entry_t *te)
{
  (void)te; // Suppress unused parameter warning
  // No action needed - locks are released immediately in get_ticket_entry
}