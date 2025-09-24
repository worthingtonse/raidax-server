/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : crossover.c
#   Last Modified : 2024-08-09 21:44
#   Describe      : This file implements indexing for coin crossovers.
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
#include <time.h>

#include "commands.h"
#include "crossover.h"
#include "log.h"
#include "db.h"
#include "utils.h"
#include "config.h"
#include "net.h"
#include "aes.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>

extern struct config_s config;

struct crossover_index_entry *crossover_index[MAX_CROSSOVER_RECORDS];
pthread_mutex_t crossover_mtx;

// This was in the original cmd_crossover.c but not in the header.
// It's better to keep it file-static if only used here.
char *get_crypto_key(char *ticker, int *size);

/*
 * Initializes crossover index and the optimized crossover thread.
 */
int init_crossover_index(void)
{
  pthread_t crossover_thread_handle;
  int rc;

  debug("Initializing crossover index");

  rc = pthread_mutex_init(&crossover_mtx, NULL);
  if (rc != 0)
  {
    error("Failed to init crossover mtx: %s", strerror(rc));
    return -1;
  }

  // Safely initialize the index
  if (pthread_mutex_lock(&crossover_mtx) != 0)
  {
    error("Failed to lock crossover mutex during init");
    return -1;
  }
  for (int i = 0; i < MAX_CROSSOVER_RECORDS; i++)
    crossover_index[i] = NULL;
  pthread_mutex_unlock(&crossover_mtx);

  if (pthread_create(&crossover_thread_handle, NULL, crossover_thread, NULL) != 0)
  {
    error("Failed to start crossover thread: %s", strerror(errno));
    return -1;
  }

  debug("Crossover thread initialized");
  return 0;
}

/*
 * ** OPTIMIZED Background Thread **
 * Main loop that runs periodically. Instead of a fixed sleep, it now
 * dynamically calculates how long to sleep based on the closest expiry time
 * of an active transaction. This makes it more responsive and efficient.
 */
void *crossover_thread(void *arg)
{
  while (1)
  {
    housekeeping_crossover_index();

    time_t now;
    time(&now);
    time_t next_expiry = 0;

    if (pthread_mutex_lock(&crossover_mtx) != 0)
    {
      error("Crossover thread failed to lock mutex, skipping cycle.");
      sleep(CROSSOVER_HOUSEKEEPING_PERIOD); // Sleep for a default period before retrying
      continue;
    }

    for (int i = 0; i < MAX_CROSSOVER_RECORDS; i++)
    {
      if (crossover_index[i] != NULL)
      {
        time_t expiry_time = crossover_index[i]->first_seen + CROSSOVER_EXPIRY;
        if (next_expiry == 0 || expiry_time < next_expiry)
        {
          next_expiry = expiry_time;
        }
      }
    }
    pthread_mutex_unlock(&crossover_mtx);

    int sleep_duration = CROSSOVER_HOUSEKEEPING_PERIOD;
    if (next_expiry > 0)
    {
      if (next_expiry > now)
      {
        sleep_duration = next_expiry - now;
      }
      else
      {
        sleep_duration = 1; // An item has already expired, wake up soon.
      }
    }

    if (sleep_duration > CROSSOVER_HOUSEKEEPING_PERIOD)
    {
      sleep_duration = CROSSOVER_HOUSEKEEPING_PERIOD;
    }

    debug("Crossover thread sleeping for %d seconds.", sleep_duration);
    sleep(sleep_duration);
  }
  return NULL;
}

/*
 * Removes stale crossover records from the index.
 */
void housekeeping_crossover_index(void)
{
  time_t now;
  struct crossover_index_entry *cie;

  debug("Housekeeping crossover index...");
  time(&now);

  if (pthread_mutex_lock(&crossover_mtx) != 0)
  {
    error("Housekeeping failed to lock crossover mutex.");
    return;
  }

  for (int i = 0; i < MAX_CROSSOVER_RECORDS; i++)
  {
    if (crossover_index[i] == NULL)
      continue;

    cie = crossover_index[i];
    if (cie->first_seen + CROSSOVER_EXPIRY < now)
    {
      debug("Removing expired crossover entry %d.", i);
      free(cie);
      crossover_index[i] = NULL;
    }
  }

  if (pthread_mutex_unlock(&crossover_mtx) != 0)
  {
    error("Housekeeping failed to unlock crossover mutex.");
  }
}

/*
 * Adds a new crossover transaction entry to the index.
 */
int add_crossover_index_entry(char *locker_key, char *currency_code, uint64_t amount,
                              char *sender_address, int address_size, unsigned char *receipt_id, char *memo, int memo_length)
{

  struct crossover_index_entry *cie = NULL;
  int i;
  int empty_slot = -1;

  if (pthread_mutex_lock(&crossover_mtx) != 0)
  {
    error("Failed to lock crossover mutex to add entry.");
    return -1;
  }

  for (i = 0; i < MAX_CROSSOVER_RECORDS; i++)
  {
    if (crossover_index[i] == NULL)
    {
      empty_slot = i;
      break;
    }
  }

  if (empty_slot == -1)
  {
    error("Crossover index is full");
    pthread_mutex_unlock(&crossover_mtx);
    return -2;
  }

  cie = (struct crossover_index_entry *)malloc(sizeof(struct crossover_index_entry));
  if (cie == NULL)
  {
    error("Failed to allocate memory for crossover index entry");
    pthread_mutex_unlock(&crossover_mtx);
    return -1;
  }

  cie->completed = 0;
  cie->amount = amount;
  memcpy(cie->locker_key, locker_key, 16);
  memcpy(cie->currency_code, currency_code, 3);
  memcpy(cie->sender_address, sender_address, 32);
  memcpy(cie->receipt_id, receipt_id, 16);
  if (memo && memo_length > 0)
  {
    int len_to_copy = (memo_length < MAX_MEMO_SIZE) ? memo_length : MAX_MEMO_SIZE;
    memcpy(cie->memo, memo, len_to_copy);
    cie->memo[len_to_copy] = '\0';
  }
  else
  {
    cie->memo[0] = '\0';
  }
  cie->address_size = address_size;
  time(&cie->first_seen);

  crossover_index[empty_slot] = cie;

  pthread_mutex_unlock(&crossover_mtx);

  debug("Added new crossover entry at index %d", empty_slot);
  return 0;
}

struct crossover_index_entry *get_crossover_index_entry(char *locker_key)
{
  struct crossover_index_entry *cie = NULL;
  int i;

  if (pthread_mutex_lock(&crossover_mtx) != 0)
  {
    error("Failed to lock crossover mutex to get entry.");
    return NULL;
  }

  for (i = 0; i < MAX_CROSSOVER_RECORDS; i++)
  {
    if (crossover_index[i] == NULL)
      continue;

    if (!memcmp(crossover_index[i]->locker_key, locker_key, 16))
    {
      debug("Found crossover index entry at %d", i);
      cie = crossover_index[i];
      break;
    }
  }

  if (pthread_mutex_unlock(&crossover_mtx) != 0)
  {
    error("Failed to unlock crossover mutex after getting entry.");
  }

  return cie;
}

int check_depository(char *locker_key, char *currency_code, unsigned char *transaction_id, unsigned char *receipt_id, char *memo, int memo_length)
{
  struct crossover_index_entry *cie = NULL;
  uint8_t status;
  int olength;
  uint64_t amount, nbamount;
  char *response_body;
  char buf[76 + 1500];

  debug("Checking depository. Needed confirmations %d", config.btc_confirmations);

  cie = get_crossover_index_entry(locker_key);
  if (cie == NULL)
  {
    error("No index entry found for depository check");
    return ERROR_NO_ENTRY;
  }

  if (memcmp(cie->receipt_id, receipt_id, 16))
  {
    error("Wrong ReceiptID for depository check");
    return ERROR_INVALID_PARAMETER;
  }

  memset(buf, 0, sizeof(buf));
  if (memcmp(cie->currency_code, currency_code, 3))
  {
    error("Wrong ticker %c%c%c", cie->currency_code[0], cie->currency_code[1], cie->currency_code[2]);
    return ERROR_INVALID_PARAMETER;
  }

  memcpy(buf, cie->currency_code, 3);
  nbamount = swap_uint64(cie->amount);
  memcpy(buf + 3, (char *)&nbamount, 8);
  memcpy(buf + 3 + 8, cie->locker_key, 16);
  buf[3 + 8 + 16] = (char)config.btc_confirmations;
  memcpy(buf + 3 + 8 + 16 + 1, cie->receipt_id, 16);
  memcpy(buf + 3 + 8 + 16 + 1 + 16, transaction_id, 32);
  memcpy(buf + 3 + 8 + 16 + 1 + 16 + 32, memo, memo_length);

  response_body = proxy_request(CMD_PROXY_WATCH_FOR_TRANSACTION, buf, 76 + memo_length, &olength, &status);
  if (response_body == NULL || (status != STATUS_SUCCESS && status != STATUS_TX_SEEN))
  {
    error("Invalid response from proxy. Status %u", status);
    if (response_body != NULL)
      free(response_body);
    return status;
  }

  nbamount = *((uint64_t *)&response_body[0]);
  amount = swap_uint64(nbamount);

  if (amount != cie->amount)
  {
    error("Invalid amount from proxy. Expected %llu, got %llu", (unsigned long long)cie->amount, (unsigned long long)amount);
    free(response_body);
    return ERROR_AMOUNT_MISMATCH;
  }

  cie->confirmations = swap_uint64(*((uint64_t *)&response_body[16]));
  free(response_body);

  if (status == STATUS_TX_SEEN)
  {
    debug("Transaction seen but not confirmed");
    return status;
  }

  cie->completed = 1;
  debug("Transaction confirmed");
  return 0;
}

int get_exchange_rate(char *currency_code, long long int *er)
{
  char body[3];
  char *response_body;
  uint8_t status;
  int olength;

  debug("Get exchange rate for %c%c%c", currency_code[0], currency_code[1], currency_code[2]);
  if (memcmp(currency_code, "BTC", 3))
  {
    error("Invalid currency ticker for exchange rate");
    return ERROR_INVALID_PARAMETER;
  }

  memcpy(body, currency_code, 3);
  response_body = proxy_request(CMD_PROXY_GET_RATE, &body[0], 3, &olength, &status);
  if (response_body == NULL || status != STATUS_SUCCESS)
  {
    error("Invalid response from proxy for get_rate. Status %u", status);
    if (response_body != NULL)
      free(response_body);
    return status;
  }

  if (olength != 8)
  {
    error("Invalid length returned for exchange rate: %d", olength);
    if (response_body != NULL)
      free(response_body);
    return ERROR_PROXY;
  }

  *er = swap_uint64(*(long long int *)response_body);
  debug("Rate retrieved %llu", (unsigned long long)*er);
  free(response_body);
  return 0;
}

int withdraw_from_depository(char *locker_key, char *currency_code, uint64_t conversion_cost, char *target_address, int address_size, unsigned char *receipt_id, char *memo, int memo_length)
{
  char body[155 + 1500];
  char *response_body;
  uint8_t status;
  int olength;
  uint64_t nbamount;
  int btc_key_size = 0;
  char *btc_key = NULL;

  debug("Sending Crypto. Locker: %s, Cost: %llu, Currency: %s", locker_key, (unsigned long long)conversion_cost, currency_code);

  if (memcmp(currency_code, "BTC", 3) != 0)
  {
    error("Invalid currency ticker for withdrawal");
    return ERROR_INVALID_PARAMETER;
  }

  btc_key = get_crypto_key("BTC", &btc_key_size);
  if (btc_key == NULL)
  {
    error("Failed to get BTC key. Was it uploaded?");
    return ERROR_NO_PRIVATE_KEY;
  }

  if (btc_key_size > 3000)
  {
    error("Crypto key part is too big");
    free(btc_key);
    return ERROR_INTERNAL;
  }

  nbamount = swap_uint64(conversion_cost);
  memset(body, 0, sizeof(body));

  int current_offset = 0;
  memcpy(body + current_offset, currency_code, 3);
  current_offset += 3;
  memcpy(body + current_offset, receipt_id, 16);
  current_offset += 16;
  memcpy(body + current_offset, btc_key, btc_key_size);
  current_offset += btc_key_size;
  memcpy(body + current_offset, (char *)&nbamount, 8);
  current_offset += 8;
  memcpy(body + current_offset, locker_key, 16);
  current_offset += 16;
  body[current_offset] = (char)address_size;
  current_offset += 1;
  memcpy(body + current_offset, target_address, address_size);
  current_offset += address_size;
  memcpy(body + current_offset, memo, memo_length);
  current_offset += memo_length;

  free(btc_key);

  response_body = proxy_request(CMD_PROXY_SEND_TRANSACTION, body, current_offset, &olength, &status);
  if (response_body == NULL || (status != STATUS_SUCCESS && status != STATUS_WAITING))
  {
    error("Invalid response from proxy. Status %u", status);
    if (response_body != NULL)
      free(response_body);
    return status;
  }

  if (status == STATUS_WAITING)
  {
    debug("Proxy is waiting for other RAIDA servers.");
    if (response_body != NULL)
      free(response_body);
    return status;
  }

  debug("Crypto withdrawn from depository. Response length: %d", olength);
  free(response_body);
  return 0;
}

char *proxy_request(int command_no, char *body, int body_size, int *output_length, uint8_t *status)
{
  char *host = config.proxy_addr;
  uint16_t port = config.proxy_port;
  struct timeval tv;
  int sk, rv;
  struct sockaddr_in sa;
  unsigned char *cmd;
  unsigned char output_header[RESPONSE_HEADER_SIZE];
  uint32_t size;
  char *response_body_buf;
  fd_set myset;
  socklen_t lon;
  int valopt;
  unsigned char nonce[16];
  int total_body_size;

  debug("Sending proxy request cmd:%d to %s:%d (body size %d)", command_no, host, port, body_size);
  *status = ERROR_PROXY_CONNECT;

  sk = socket(AF_INET, SOCK_STREAM, 0);
  if (sk < 0)
  {
    error("Failed to create socket: %s", strerror(errno));
    return NULL;
  }

  tv.tv_sec = RAIDA_SERVER_RCV_TIMEOUT;
  tv.tv_usec = 0;
  setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  set_nonblocking(sk);

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  inet_pton(AF_INET, host, &sa.sin_addr);

  rv = connect(sk, (struct sockaddr *)&sa, sizeof(sa));
  if (rv < 0 && errno != EINPROGRESS)
  {
    error("Failed to connect to Proxy: %s", strerror(errno));
    close(sk);
    return NULL;
  }

  if (rv < 0)
  {
    FD_ZERO(&myset);
    FD_SET(sk, &myset);
    tv.tv_sec = RAIDA_SERVER_RCV_TIMEOUT;
    tv.tv_usec = 0;
    if (select(sk + 1, NULL, &myset, NULL, &tv) > 0)
    {
      lon = sizeof(int);
      getsockopt(sk, SOL_SOCKET, SO_ERROR, (void *)&valopt, &lon);
      if (valopt)
      {
        error("Socket error on connect: %s", strerror(valopt));
        close(sk);
        return NULL;
      }
    }
    else
    {
      error("Proxy Connection timeout");
      close(sk);
      return NULL;
    }
  }

  set_blocking(sk);

  total_body_size = 16 + body_size + 2;
  cmd = malloc(REQUEST_HEADER_SIZE + total_body_size);
  if (!cmd)
  {
    close(sk);
    return NULL;
  }

  // Construct command header
  cmd[0] = 1;
  cmd[1] = 0;
  cmd[2] = 25;
  cmd[3] = 0;
  cmd[4] = CROSSOVER;
  cmd[5] = command_no;
  cmd[6] = (config.coin_id >> 8) & 0xff;
  cmd[7] = (config.coin_id) & 0xff;
  cmd[8] = 1;
  cmd[9] = 0;
  cmd[10] = 0;
  cmd[11] = 0;
  cmd[12] = 0;
  cmd[13] = 0;
  cmd[14] = 0;
  cmd[15] = 0;
  cmd[16] = ENCRYPTION_TYPE_AES;
  cmd[17] = config.raida_no;
  cmd[18] = 0;
  cmd[19] = 0;
  cmd[20] = 0;
  cmd[21] = 0;

  memset(&cmd[24], 0, 8);
  memcpy(nonce, &cmd[24], 8);
  memcpy(&cmd[32], "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b", 12);
  uint32_t crc = crc32b(&cmd[32], 12);
  put_u32(crc, &cmd[44]);

  memcpy(&cmd[48], body, body_size);
  crypt_ctr(config.proxy_key, &cmd[32], 16 + body_size, nonce);

  cmd[REQUEST_HEADER_SIZE + total_body_size - 2] = 0x3e;
  cmd[REQUEST_HEADER_SIZE + total_body_size - 1] = 0x3e;

  send(sk, cmd, REQUEST_HEADER_SIZE + total_body_size, 0);
  free(cmd);

  if (recv(sk, output_header, RESPONSE_HEADER_SIZE, MSG_WAITALL) != RESPONSE_HEADER_SIZE)
  {
    close(sk);
    return NULL;
  }

  *status = output_header[2];
  if (*status != STATUS_SUCCESS && *status != STATUS_WAITING)
  {
    close(sk);
    return NULL;
  }

  size = (output_header[9] << 16) | (output_header[10] << 8) | output_header[11];
  if (size == 0)
  {
    close(sk);
    *output_length = 0;
    return calloc(1, 1);
  }

  response_body_buf = malloc(size);
  if (!response_body_buf)
  {
    close(sk);
    return NULL;
  }

  if (recv(sk, response_body_buf, size, MSG_WAITALL) != size)
  {
    free(response_body_buf);
    close(sk);
    return NULL;
  }
  close(sk);

  if (response_body_buf[size - 2] != 0x3e || response_body_buf[size - 1] != 0x3e)
  {
    free(response_body_buf);
    return NULL;
  }

  *output_length = size - 2;
  crypt_ctr(config.proxy_key, response_body_buf, *output_length, nonce);

  return response_body_buf;
}
