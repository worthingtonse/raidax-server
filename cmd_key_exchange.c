/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_key_exchange.c
#   Last Modified : 2025-07-30 15:30
#   Describe      : Key Exchange Commands, updated for On-Demand Page Cache.
#
#
# ====================================================*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "db.h"
#include "config.h"
#include "utils.h"
#include "net.h"
#include "aes.h"

extern struct config_s config;

/*

 * Generates a session key based on client input and encrypts it for a recipient.
 */
void cmd_encrypt_key(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  uint32_t sn;
  int8_t den;
  struct page_s *page;
  int sn_idx;
  int r0;
  unsigned char recipient_an[16];

  debug("CMD Encrypt Key");

  // Original body size check
  if (ci->body_size != 31)
  {
    error("Invalid command length: %d. Need 31", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  // Get DN and SN of the recipient
  den = ((uint8_t)payload[0]);
  sn = get_sn(&payload[1]);

  // Get recipient's AN using the on-demand cache
  page = get_page_by_sn_lock(den, sn);
  if (page == NULL)
  {
    error("Invalid sn or denomination for recipient: %u -> %hhx", sn, den);
    ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
    return;
  }
  sn_idx = sn % RECORDS_PER_PAGE;
  memcpy(recipient_an, &page->data[sn_idx * 17], 16);
  unlock_page(page);

  debug("Loaded recipient coin %hhx:%u AN", den, sn);

  ci->output_size = 16;
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  // Original logic for constructing the key
  memset(ci->output, 0, 16);
  memcpy(ci->output, &payload[5], 8); // Copy first 8 bytes from payload

  srand(time(NULL));
  r0 = rand(); // Use pseudo-random as per original logic

  ci->output[8] = den;
  memcpy(ci->output + 9, &payload[1], 4); // Copy SN

  ci->output[13] = (r0 >> 8) & 0xff;
  ci->output[14] = r0 & 0xff;
  ci->output[15] = 0xff; // Final byte marker

  // Encrypt the constructed key with the recipient's AN
  crypt_ctr(recipient_an, ci->output, 16, ci->nonce);

  ci->command_status = (char)NO_ERROR;
  debug("CMD Encrypt Key finished");
}

/*
 * Decrypts messages from other RAIDA servers.
 */
void cmd_decrypt_raida_key(conn_info_t *ci)
{
  unsigned char *payload = get_body_payload(ci);
  int coin_length, total_coins;
  uint32_t sn;
  int i;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  int an, pan, p, f, rv;
  uint8_t da;
  unsigned char *ky;
  unsigned char aens[16 * 25];
  unsigned char *aen;

  uint8_t dec_den;
  uint32_t dec_sn;

  uint8_t split_id;

  uint8_t mfs;

  debug("CMD Encrypt POST Key");

  // 16CH + DN + 4SN + (at least one 2CO + SP + RA + SH + DN + 4SN + 16KY) = 26 + 2EOF
  if (ci->body_size < 49)
  {
    error("Invalid command length: %d. Need at least 49", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 23;
  if (coin_length % 26)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 26;
  debug("Requested %d coins to auth", total_coins);

  // Get DN and SN of who the key is for
  den = ((uint8_t)payload[0]);
  sn = get_sn(&payload[1]);

  mfs = get_mfs();

  debug("Coin used for decryption %hhx:%u", den, sn);
  rv = load_my_enc_coin(den, sn, aens);
  if (rv < 0)
  {
    error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx", i, sn, den);
    ci->command_status = ERROR_COIN_LOAD;
    return;
  }

  // possible buf for mixed response. It is freed by another function
  // don't set output size here
  ci->output = (unsigned char *)malloc(total_coins);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  // all zeroes (failed coins)
  memset(ci->output, 0, total_coins);

  for (i = 0; i < total_coins; i++)
  {
    split_id = ((uint8_t)payload[21 + i * 26 + 2]);
    da = ((uint8_t)payload[21 + i * 26 + 3]);
    den = ((uint8_t)payload[21 + i * 26 + 5]);
    sn = get_sn(&payload[21 + i * 26 + 6]);
    ky = (unsigned char *)&payload[21 + i * 26 + 10];

    if (da > 24)
    {
      error("Invalid Raida passed for coin %d, sn %d -> %hhx. Raida %d Skipping it", i, sn, den, da);
      ci->output[i] = 0x0;
      f++;
      continue;
    }

    if (split_id != 0 && split_id != 1)
    {
      error("Invalid split_id passed for coin %d, sn %d -> %hhx. Split %d Skipping it", i, sn, den, split_id);
      ci->output[i] = 0x0;
      f++;
      continue;
    }

    debug("den %hhx, SN %u, Da %u, Split %u", den, sn, da, split_id);
    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %d -> %hhx. Skipping it", i, sn, den);
      ci->output[i] = 0x0;
      f++;
      continue;
    }

    aen = &aens[da * 25]; // not sure
    debug("KY %02x%02x%02x%02x%02x%02x%02x%02x ... %02x%02x ", ky[0], ky[1], ky[2], ky[3], ky[4], ky[5], ky[6], ky[7], ky[14], ky[15]);
    debug("MY AN %02x%02x%02x%02x%02x%02x%02x%02x ... %02x%02x ", aen[0], aen[1], aen[2], aen[3], aen[4], aen[5], aen[6], aen[7], aen[14], aen[15]);

    crypt_ctr(&aens[da], ky, 16, ci->nonce);
    debug("KY DECRYPTED %02x%02x%02x%02x%02x%02x%02x%02x ... %02x%02x ", ky[0], ky[1], ky[2], ky[3], ky[4], ky[5], ky[6], ky[7], ky[14], ky[15]);

    if (ky[15] != 0xff)
    {
      error("Malformed coin AN. Can't decrypt it properly");
      ci->output[i] = 0x0;
      f++;
      continue;
    }

    dec_den = (uint8_t)ky[8];
    dec_sn = get_sn(&ky[9]);

    if (dec_den != den || dec_sn != sn)
    {
      error("Decrypted coin %hhx:%u does not match what was sent %hhx:%u", dec_den, dec_sn, den, sn);
      ci->output[i] = 0x0;
      f++;
      continue;
    }

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Failed to load page for %hhx:%u", den, sn);
      ci->output[i] = 0x0;
      f++;
      continue;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    memcpy(&page->data[sn_idx * 17 + split_id * 8], ky, 8);
    page->data[sn_idx * 17 + 16] = mfs;
    page->is_dirty = 1;

    unlock_page(page);
    update_free_pages_bitmap(den, sn, 0);

    ci->output[i] = 0x1; // accepted
    p++;
  }

  ci->command_status = (char)STATUS_SUCCESS;
  ci->output_size = total_coins;

  debug("Accepted %d, failed %d", p, f);

  debug("CMD POST Key Finished");
}

/*
 * Loads an encryption coin from a local file.
 */
int load_my_enc_coin(uint8_t den, uint32_t sn, unsigned char *buf)
{
  char path[PATH_MAX];
  char tmp_buf[440];
  uint16_t coin_id;
  int fd, rv;

  sprintf((char *)&path, "%s/coins/%02hhx.%u.bin", config.cwd, den, sn);
  fd = open(path, O_RDONLY);
  if (fd < 0)
  {
    error("Failed to open coin file %s: %s", path, strerror(errno));
    return -1;
  }

  rv = read(fd, tmp_buf, 440);
  close(fd);

  if (rv != 440)
  {
    error("Invalid coin file size: %d for %s", rv, path);
    return -1;
  }

  coin_id = (tmp_buf[2] << 8) | tmp_buf[3];
  if (coin_id != config.coin_id)
  {
    error("Invalid coin id in file: %u", coin_id);
    return -1;
  }

  memcpy(buf, tmp_buf + 40, 400);
  return 0;
}

/*
 * Stores a key for the chat system.
 */
void cmd_post_key(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  char key_path[PATH_MAX];
  int fd, rv;
  uint8_t kl, ks;

  if (ci->body_size != 185)
  {
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  ks = payload[165];
  kl = payload[166];

  if (ks + kl > 127)
  {
    ci->command_status = ERROR_INVALID_KEY_LENGTH;
    return;
  }

  sprintf((char *)&key_path, "%s/Keys/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", config.cwd, payload[0], payload[1], payload[2], payload[3],
          payload[4], payload[5], payload[6], payload[7], payload[8], payload[9], payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]);

  fd = open(key_path, O_CREAT | O_WRONLY, 0640);
  if (fd < 0)
  {
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  write(fd, (unsigned char *)&payload[32], 1); // Denomination
  write(fd, (unsigned char *)&payload[33], 4); // SN
  rv = write(fd, &payload[37 + ks], kl);
  close(fd);

  if (rv != kl)
  {
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  ci->command_status = (char)STATUS_SUCCESS;
}

/*
 * Retrieves a key for the chat system.
 */
void cmd_get_key(conn_info_t *ci)
{
  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  char key_path[PATH_MAX];
  char buf[512];
  int fd, rv;

  if (ci->body_size != 55)
  {
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  sprintf((char *)&key_path, "%s/Keys/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", config.cwd, payload[0], payload[1], payload[2], payload[3],
          payload[4], payload[5], payload[6], payload[7], payload[8], payload[9], payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]);

  fd = open(key_path, O_RDONLY);
  if (fd < 0)
  {
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  rv = read(fd, &buf, 512);
  close(fd);

  if (rv < 0)
  {
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  ci->output = (unsigned char *)malloc(rv);
  if (ci->output == NULL)
  {
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  memcpy(ci->output, buf, rv);
  ci->output_size = rv;
  ci->command_status = (char)STATUS_SUCCESS;
}

/*
 * Handles a key alert.
 */
void cmd_key_alert(conn_info_t *ci)
{
  debug("CMD Key Alert Received (No Action)");
  ci->command_status = (char)STATUS_SUCCESS;
}
