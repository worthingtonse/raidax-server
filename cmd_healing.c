/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_healing.c
#   Last Modified : 2025-07-24 11:09
#   Describe      : Healing Commands, updated for dual hashing support and Free Pages Bitmap.
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
#include <sys/select.h>

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "db.h"
#include "config.h"
#include "utils.h"
#include "net.h"

extern struct config_s config;

/*
 * Get Ticket Command: Verifies coins and issues a ticket for authentic ones.
 */
void cmd_get_ticket(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int coin_length, total_coins;
  uint32_t sn;
  int i;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  int p, f;
  struct ticket_entry_t *te = NULL;

  debug("CMD Get Ticket");

  if (ci->body_size < 39)
  {
    error("Invalid command length: %d. Need 39", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 18;
  if (coin_length % 21)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 21;
  debug("Requested %d coins to auth", total_coins);

  ci->output = (unsigned char *)malloc((total_coins / 8) + 1 + 4);
  if (ci->output == NULL)
  {
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }
  memset(ci->output, 0, (total_coins / 8) + 1 + 4);

  p = f = 0;
  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[i * 21]);
    sn = get_sn(&payload[i * 21 + 1]);

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination: den=%hhx, sn=%u", den, sn);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    if (!memcmp(&page->data[sn_idx * 17], &payload[i * 21 + 5], 16))
    {
      if (te == NULL)
      {
        te = get_free_ticket_slot();
        if (te == NULL)
        {
          error("All ticket slots are busy");
          ci->command_status = ERROR_NO_TICKET_SLOT;
          unlock_page(page);
          return;
        }
      }
      ci->output[i / 8] |= 1 << (i % 8);
      p++;
      if (te->num_coins < MAX_COINS_PER_TICKET)
      {
        te->coins[te->num_coins].denomination = den;
        te->coins[te->num_coins].sn = sn;
        te->num_coins++;
      }
    }
    else
    {
      f++;
    }
    unlock_page(page);
  }

  debug("Coins authentic/failed %d/%d of %d", p, f, total_coins);

  if (p == total_coins)
  {
    ci->command_status = (char)STATUS_ALL_PASS;
    ci->output_size = 4;
    if (te)
      put_sn(te->ticket, ci->output);
  }
  else if (f == total_coins)
  {
    ci->command_status = (char)STATUS_ALL_FAIL;
  }
  else
  {
    ci->command_status = (char)STATUS_MIXED;
    ci->output_size = (total_coins + 7) / 8;
    if (te)
      put_sn(te->ticket, ci->output + ci->output_size);
    ci->output_size += 4;
  }

  if (te)
  {
    debug("Allocated ticket %x for %d coins", te->ticket, te->num_coins);
    unlock_ticket_entry(te);
  }

  debug("CMD Get Ticket finished");
}

/*
 * Validate Ticket Command: Allows another RAIDA to claim a ticket.
 */
void cmd_validate_ticket(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int i;
  struct ticket_entry_t *te;
  uint8_t ridx;
  uint32_t ticket;

  debug("CMD Validate Ticket");

  if (ci->body_size != 23)
  {
    error("Invalid command length: %d. Need 23", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  ridx = (uint8_t)payload[0];
  if (ridx >= TOTAL_RAIDA_SERVERS)
  {
    error("Invalid RAIDA id %d", ridx);
    ci->command_status = ERROR_WRONG_RAIDA;
    return;
  }

  ticket = get_u32(&payload[1]);
  debug("RAIDA%d is claiming ticket %x", ridx, ticket);

  te = get_ticket_entry(ticket);
  if (te == NULL)
  {
    error("No ticket found");
    ci->command_status = ERROR_NO_TICKET_FOUND;
    return;
  }

  if (te->claims[ridx])
  {
    error("Ticket has been claimed already by this raida (raida %d)", ridx);
    ci->command_status = ERROR_TICKET_CLAIMED_ALREADY;
    unlock_ticket_entry(te);
    return;
  }

  ci->output = (unsigned char *)malloc(te->num_coins * 5);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    unlock_ticket_entry(te);
    return;
  }
  ci->output_size = te->num_coins * 5;

  debug("Ticket %x has %d coins", te->ticket, te->num_coins);
  for (i = 0; i < te->num_coins; i++)
  {
    ci->output[i * 5] = te->coins[i].denomination;
    put_sn(te->coins[i].sn, &ci->output[i * 5 + 1]);
  }

  te->claims[ridx] = 1;
  ci->command_status = STATUS_SUCCESS;

  unlock_ticket_entry(te);

  debug("CMD Validate Ticket finished");
}

/*
 * Find Command: Checks if a coin's AN matches either the current AN or a proposed AN.
 */
void cmd_find(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int coin_length, total_coins;
  uint32_t sn;
  int i;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  int an, pan, f;

  debug("CMD Find");

  // 16CH + (at least one DN + SN + AN + PN) = 37 + 2EOF
  if (ci->body_size < 55)
  {
    error("Invalid command length: %d. Need 55", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 18;
  if (coin_length % 37)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 37;
  debug("Requested %d coins to check", total_coins);

  ci->output = (unsigned char *)malloc(total_coins);
  if (ci->output == NULL)
  {
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }
  memset(ci->output, 0, total_coins);

  an = pan = f = 0;
  for (i = 0; i < total_coins; i++)
  {
    den = ((uint8_t)payload[i * 37]);
    sn = get_sn(&payload[i * 37 + 1]);

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination passed for coin %d, sn %u -> %hhx", i, sn, den);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      return;
    }

    sn_idx = sn % RECORDS_PER_PAGE;
    if (!memcmp(&page->data[sn_idx * 17], &payload[i * 37 + 5], 16))
    {
      ci->output[i] = 0x1;
      an++;
    }
    else if (!memcmp(&page->data[sn_idx * 17], &payload[i * 37 + 21], 16))
    {
      debug("sn %u PAN matches", sn);
      ci->output[i] = 0x2;
      pan++;
    }
    else
    {
      debug("sn %u neither matches", sn);
      f++;
    }
    unlock_page(page);
  }

  debug("Coins ans/pans/failed %d/%d/%d of %d", an, pan, f, total_coins);

  if (an == total_coins)
    ci->command_status = (char)STATUS_FIND_ALL_AN;
  else if (pan == total_coins)
    ci->command_status = (char)STATUS_FIND_ALL_PAN;
  else if (f == total_coins)
    ci->command_status = (char)STATUS_FIND_NEITHER;
  else
  {
    ci->command_status = (char)STATUS_FIND_MIXED;
    ci->output_size = total_coins;
  }

  debug("CMD Find finished");
}

/*
 * Fix Command: Fixes a coin's AN based on a quorum from other RAIDA servers.
 */
void cmd_fix(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  int coin_length, total_coins;
  uint32_t sn;
  int i, j, k;
  int8_t den;
  int sn_idx;
  struct page_s *page;
  int p, f;
  unsigned char *pg;
  uint32_t ticket;
  int rv;
  pthread_t threads[TOTAL_RAIDA_SERVERS];
  struct validate_ticket_arg_t args[TOTAL_RAIDA_SERVERS];
  unsigned char new_an[16];
  unsigned char hash_input[22]; // raida_num + denomination + sn + PG
  uint8_t mfs;
  coin_counter_t *counters;
  int threads_created = 0;
  debug("CMD Fix");

  if (ci->body_size < 139)
  {
    error("Invalid command length: %d. Need 139", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  coin_length = ci->body_size - 134;
  if (coin_length % 5)
  {
    error("Can't determine the number of coins");
    ci->command_status = ERROR_COINS_NOT_DIV;
    return;
  }

  total_coins = coin_length / 5;
  debug("Requested %d coins to fix", total_coins);

  ci->output = (unsigned char *)malloc((total_coins / 8) + 1);
  if (ci->output == NULL)
  {
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }
  memset(ci->output, 0, (total_coins / 8) + 1);

  mfs = get_mfs();
  counters = (coin_counter_t *)malloc(sizeof(coin_counter_t) * total_coins);
  if (counters == NULL)
  {
    error("Can't alloc buffer for the coin counters");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  for (i = 0; i < total_coins; i++)
  {
    counters[i].coin.denomination = ((uint8_t)payload[i * 5]);
    counters[i].coin.sn = get_sn(&payload[i * 5 + 1]);
    counters[i].cnt = 1; // Initialize counter with 1 for the server's own trusted vote
  }

  for (i = 0; i < total_coins; i++)
  {
    den = counters[i].coin.denomination;
    sn = counters[i].coin.sn;

    page = get_page_by_sn_lock(den, sn);
    if (page == NULL)
    {
      error("Invalid SN or denomination: den=%hhx, sn=%u", den, sn);
      ci->command_status = ERROR_INVALID_SN_OR_DENOMINATION;
      free(counters);
      return;
    }
    unlock_page(page);
  }

  pg = &payload[total_coins * 5];
  for (i = 0; i < TOTAL_RAIDA_SERVERS; i++)
  {
    threads[i] = 0;
    ticket = get_u32(&payload[total_coins * 5 + 16 + i * 4]);

    args[i].raida_idx = i;
    args[i].ticket = ticket;
    args[i].ci = ci;
    args[i].rv_coins = NULL;
    args[i].rv_num_coins = 0;
    rv = pthread_create(&threads[i], NULL, send_validate_ticket_job, &args[i]);
    if (rv < 0)
    {
      error("Failed to create a thread for RAIDA%d: %s", i, strerror(errno));
      threads[i] = 0;
    }
    else
    {
      threads_created = i + 1;
    }
  }

  debug("Waiting for responses from RAIDA servers");
  for (i = 0; i < threads_created; i++)
  {
    if (threads[i] == 0)
      continue;
    pthread_join(threads[i], NULL);

    if (args[i].rv_num_coins > 0)
    {
      for (j = 0; j < args[i].rv_num_coins; j++)
      {
        for (k = 0; k < total_coins; k++)
        {
          if (args[i].rv_coins[j].denomination == counters[k].coin.denomination &&
              args[i].rv_coins[j].sn == counters[k].coin.sn)
          {
            counters[k].cnt++;
            break;
          }
        }
      }
      free(args[i].rv_coins);
    }
  }

  p = f = 0;
  for (k = 0; k < total_coins; k++)
  {
    den = counters[k].coin.denomination;
    sn = counters[k].coin.sn;
    if (counters[k].cnt > (TOTAL_RAIDA_SERVERS / 2) + 1)
    {
      debug("Updating AN for den:%hhx, sn:%u", den, sn);
      page = get_page_by_sn_lock(den, sn);
      if (page == NULL)
      {
        f++;
        continue;
      }

      ci->output[k / 8] |= 1 << (k % 8);
      sn_idx = sn % RECORDS_PER_PAGE;
      p++;

      hash_input[0] = config.raida_no;
      hash_input[1] = den;
      put_sn(sn, &hash_input[2]);
      memcpy(&hash_input[6], pg, 16);

      generate_an_hash_legacy(hash_input, 22, new_an);
      memcpy(&page->data[sn_idx * 17], new_an, 16);
      page->data[sn_idx * 17 + 16] = mfs;
      page->is_dirty = 1; // Mark page as dirty

      // ** NEW: Update bitmap to mark the fixed coin as 'not free' **
      update_free_pages_bitmap(den, sn, 0);

      unlock_page(page);
    }
    else
    {
      f++;
    }
  }
  free(counters);

  if (p == total_coins)
    ci->command_status = (char)STATUS_ALL_PASS;
  else if (f == total_coins)
    ci->command_status = (char)STATUS_ALL_FAIL;
  else
  {
    ci->command_status = (char)STATUS_MIXED;
    ci->output_size = (total_coins + 7) / 8;
  }

  debug("CMD Fix finished");
}

/*
 * This function runs in a separate thread to validate a ticket with another RAIDA server.
 */
/*
 * This function runs in a separate thread to validate a ticket with another RAIDA server.
 */
void *send_validate_ticket_job(void *arg)
{
  struct validate_ticket_arg_t *vat = (struct validate_ticket_arg_t *)arg;
  int sk, rv;
  unsigned char cmd[REQUEST_HEADER_SIZE + 23]; // Header + body for validate_ticket
  unsigned char output_header[RESPONSE_HEADER_SIZE];
  unsigned char *body_buf;

  int i;
  uint32_t sn;
  int8_t denomination;
  struct page_s *page;
  struct timeval tv, tvc;
  int srv;
  struct sockaddr_in *sa;
  fd_set myset;
  socklen_t lon;
  int valopt;
  uint32_t crc; // Restored for clarity

  //  FIX: Prevent server from connecting to itself ***
  if (vat->raida_idx == config.raida_no)
  {
    debug("Skipping validate_ticket to ourselves (RAIDA%d) as we already self-voted.", vat->raida_idx);
    return NULL;
  }

  sk = socket(AF_INET, SOCK_STREAM, 0);
  if (sk < 0)
  {
    error("Failed to create socket for RAIDA%d: %s", vat->raida_idx, strerror(errno));
    return NULL;
  }

  // Restore timeout logic
  tv.tv_sec = RAIDA_SERVER_RCV_TIMEOUT;
  tv.tv_usec = 0;
  if (setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
  {
    error("Failed to set RCV timeout for RAIDA%d: %s", vat->raida_idx, strerror(errno));
    close(sk);
    return NULL;
  }
  if (setsockopt(sk, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
  {
    error("Failed to set SND timeout for RAIDA%d: %s", vat->raida_idx, strerror(errno));
    close(sk);
    return NULL;
  }

  sa = (struct sockaddr_in *)config.raida_addrs[vat->raida_idx];

  // Restore original non-blocking connect with select() for timeout
  if (set_nonblocking(sk) < 0)
  {
    error("Failed to put socket in non-blocking mode for RAIDA%d", vat->raida_idx);
    close(sk);
    return NULL;
  }

  rv = connect(sk, (struct sockaddr *)sa, sizeof(struct sockaddr));
  if (rv < 0)
  {
    if (errno == EINPROGRESS)
    {
      do
      {
        tvc.tv_sec = RAIDA_SERVER_RCV_TIMEOUT;
        tvc.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(sk, &myset);
        srv = select(sk + 1, NULL, &myset, NULL, &tvc);
        if (srv < 0 && errno != EINTR)
        {
          error("Error connecting to RAIDA%d: %s", vat->raida_idx, strerror(errno));
          close(sk);
          return NULL;
        }
        else if (srv > 0)
        {
          lon = sizeof(int);
          if (getsockopt(sk, SOL_SOCKET, SO_ERROR, (void *)&valopt, &lon) < 0)
          {
            error("Failed to check error for RAIDA%d: %s", vat->raida_idx, strerror(errno));
            close(sk);
            return NULL;
          }
          if (valopt)
          {
            error("Socket error for RAIDA%d: %d, %s", vat->raida_idx, valopt, strerror(valopt));
            close(sk);
            return NULL;
          }
          break; // Connection established
        }
        else
        {
          error("RAIDA%d Connection timeout", vat->raida_idx);
          close(sk);
          return NULL;
        }
      } while (1);
    }
    else
    {
      error("Failed to connect to RAIDA%d: %s", vat->raida_idx, strerror(errno));
      close(sk);
      return NULL;
    }
  }

  if (set_blocking(sk) < 0)
  {
    error("Failed to put socket back in blocking mode for RAIDA%d", vat->raida_idx);
    close(sk);
    return NULL;
  }

  // ** RESTORED: Building the request packet exactly as in the original code **
  cmd[0] = 1;
  cmd[1] = 0;
  cmd[2] = vat->raida_idx;
  cmd[3] = 0;
  cmd[4] = 2;                              // command group
  cmd[5] = 50;                             // validate ticket
  cmd[6] = (vat->ci->coin_id >> 8) & 0xff; // CoinID
  cmd[7] = (vat->ci->coin_id) & 0xff;      // CoinID
  cmd[8] = 1;                              // PL
  cmd[9] = 0;                              // AP
  cmd[10] = 0;                             // AP
  cmd[11] = 0;                             // Compression
  cmd[12] = 0;                             // Translation
  cmd[13] = 0;                             // AI
  cmd[14] = 0;                             // Reserved
  cmd[15] = 0;                             // Reserved
  cmd[16] = 0;                             // Encryption Type
  cmd[17] = 0;                             // Denomination of the encryption coin
  cmd[18] = 0;                             // SN of the encryption coin
  cmd[19] = 0;                             // SN of the encryption coin
  cmd[20] = 0;                             // SN of the encryption coin
  cmd[21] = 0;                             // SN of the encryption coin

  cmd[22] = 0;              // BodyLength Byte0
  cmd[23] = 16 + 1 + 4 + 2; // BodyLength Byte1

  // ** RESTORED: Explicitly zeroing the nonce field **
  memset(&cmd[24], 0, 8); // Nonce

  // Body. Challenge
  for (i = 0; i < 12; i++)
  {
    cmd[32 + i] = i;
  }

  // Crc
  crc = crc32b(&cmd[32], 12);
  put_u32(crc, &cmd[44]);

  // Our RAIDA idx
  cmd[48] = config.raida_no;

  // Ticket
  put_u32(vat->ticket, &cmd[49]);

  // Trailer
  cmd[53] = 0x3e;
  cmd[54] = 0x3e;

  if (send(sk, cmd, sizeof(cmd), 0) < 0)
  {
    error("Failed to send request to RAIDA%d: %s", vat->raida_idx, strerror(errno));
    close(sk);
    return NULL;
  }

  if (recv(sk, output_header, RESPONSE_HEADER_SIZE, MSG_WAITALL) != RESPONSE_HEADER_SIZE)
  {
    error("Failed to read header from RAIDA%d: %s", vat->raida_idx, strerror(errno));
    close(sk);
    return NULL;
  }

  if (output_header[2] != STATUS_SUCCESS)
  {
    debug("RAIDA%d returned non-success status: %d", vat->raida_idx, output_header[2]);
    close(sk);
    return NULL;
  }

  uint32_t size = (output_header[9] << 16) | (output_header[10] << 8) | output_header[11];
  if (size < 2 || (size - 2) % 5 != 0)
  {
    error("RAIDA%d returned invalid body size: %u", vat->raida_idx, size);
    close(sk);
    return NULL;
  }

  body_buf = malloc(size);
  if (!body_buf)
  {
    error("Failed to allocate memory for RAIDA%d response body", vat->raida_idx);
    close(sk);
    return NULL;
  }

  if (recv(sk, body_buf, size, MSG_WAITALL) != size)
  {
    error("Failed to read body from RAIDA%d: %s", vat->raida_idx, strerror(errno));
    free(body_buf);
    close(sk);
    return NULL;
  }
  close(sk);

  if (body_buf[size - 2] != 0x3e || body_buf[size - 1] != 0x3e)
  {
    error("Invalid trailer bytes from RAIDA%d", vat->raida_idx);
    free(body_buf);
    return NULL;
  }

  int total_coins = (size - 2) / 5;
  vat->rv_coins = malloc(sizeof(coin_t) * total_coins);
  if (!vat->rv_coins)
  {
    error("Failed to alloc memory for coins from RAIDA%d", vat->raida_idx);
    free(body_buf);
    return NULL;
  }

  //: Redundant local check block **
  for (i = 0; i < total_coins; i++)
  {
    denomination = body_buf[i * 5];
    sn = get_sn(&body_buf[i * 5 + 1]);

    debug("RAIDA%d received vote for Denomination %hhx, sn %u", vat->raida_idx, denomination, sn);
    page = get_page_by_sn_lock(denomination, sn);
    if (page == NULL)
    {
      error("Invalid sn or denomination received from RAIDA%d, sn %u -> %hhx", vat->raida_idx, sn, denomination);
      free(body_buf);
      free(vat->rv_coins);
      vat->rv_coins = NULL;
      return NULL;
    }
    unlock_page(page);

    vat->rv_coins[i].denomination = denomination;
    vat->rv_coins[i].sn = sn;
  }

  free(body_buf);
  vat->rv_num_coins = total_coins;

  debug("validate_ticket completed for RAIDA%d", vat->raida_idx);
  return NULL;
}