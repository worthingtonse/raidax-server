/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium 
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : auth.c
#   Last Modified : 2023-07-20 15:25
#   Describe      : 
#
# ====================================================*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "../log.h"
#include "../protocol.h"
#include "../commands.h"
#include "../db.h"
#include "../config.h"
#include "../utils.h"
#include "common.h"


// Detect CC2
int cc2_detect(unsigned char *payload, int total_coins, int *p, int *f, unsigned char *output) {
  int rv;
  unsigned char tan[32];
  unsigned char an[16];
  unsigned char *can;
  uint32_t sn;
  int i;
  int sock;
  char *buf, obuf[12], *obufrest;
  uint8_t status;
  uint16_t rbl;
  int exp_bytes, c;


  // 3SN + 16AN
  buf = alloc_cc2_packet(total_coins * 19);
  if (buf == NULL) {
    error("Failed to allocate CC2 packet");
    return ERROR_LEGACY_DB;
  }

  debug("Detecting  %d cc2 coins", total_coins);

  sock = init_cc2_socket();
  if (sock < 0) {
    error("Failed to connect to UNIX socket");
    return ERROR_LEGACY_DB;
  }
  /*
CH CH CH CH CH CH CH CH CH CH CH CH CH CH CH CH
SN SN SN AN AN AN AN AN AN AN AN AN AN AN AN AN AN AN AN 
SN SN SN AN AN AN AN AN AN AN AN AN AN AN AN AN AN AN AN 
SN SN SN AN AN AN AN AN AN AN AN AN AN AN AN AN AN AN AN 
SN SN SN AN AN AN AN AN AN AN AN AN AN AN AN AN AN AN AN 
3E 3E //Not Encryption
*/
  for (i = 0; i < total_coins; i++) {
    sn = get_sn(&payload[i * 21 + 1]);
    can = &payload[i * 21 + 5];

    // SN
    buf[22 + 16 + i * 19] = (sn >> 16) & 0xff;
    buf[22 + 16 + i * 19 + 1] = (sn >> 8) & 0xff;
    buf[22 + 16 + i * 19 + 2] = sn & 0xff;

    // AN
    memcpy(buf + 22 + 16 + i * 19 + 3, &payload[i * 21 + 5], 16); 
    debug("comp sn %d %02x%02x%02x...%02x%02x ", sn, can[0], can[1], can[2], can[14], can[15]);
  }

  debug("Launching detect2");


  rv = send(sock, buf, 22 + 16 + total_coins * 19 + 2, 0);
  if (rv < 0) {
    error("Failed to send data to UNIX: %s", strerror(errno));
    free(buf);
    close(sock);
    return ERROR_LEGACY_DB;
  }

  free(buf);

  rv = recv(sock, obuf, 12, MSG_WAITALL);
  if (rv < 0) {
    error("Failed to read header from UNIX: %s", strerror(errno));
    close(sock);
    return ERROR_LEGACY_DB;
  }

  if (rv != 12) {
    error("Failed to read full header from UNIX. rv is %d", rv);
    close(sock);
    return ERROR_LEGACY_DB;
  }

  status = (int) obuf[2];

  debug("RAIDA replied with %u", status);
  if (status == 242) {
    (*f) = total_coins;
  } else if (status == 241) {
    (*p) = total_coins;
  } else if (status == 243) {

    rbl = (obuf[9] >> 16) | (obuf[10] >> 8) | (obuf[11]);
    debug("Mixed. Will read %d bytes minus header", rbl);

    if (rbl < 13) {
      error("Failed to get full body from UNIX. Body length is %d", rbl);
      close(sock);
      return ERROR_LEGACY_DB;
    }

    // Header size
    rbl -= 12;

    obufrest = (char *) malloc(sizeof(char) * rbl);
    if (obufrest == NULL) {
      error("Failed to alloc full body from UNIX. Body length is %d", rbl);
      close(sock);
      return ERROR_LEGACY_DB;
    }

    rv = recv(sock, obufrest, rbl, MSG_WAITALL);
    if (rv < 0) {
      error("Failed to read full body from UNIX: %s", strerror(errno));
      free(obufrest);
      close(sock);
      return ERROR_LEGACY_DB;
    }

    exp_bytes = total_coins / 8;
    if (total_coins % 8) {
      exp_bytes += 1;
    }

    if (rv != rbl || rv != exp_bytes)  {
      error("Failed to read full body from UNIX. rv is %d. Expected %d", rv, exp_bytes);
      free(obufrest);
      close(sock);
      return ERROR_LEGACY_DB;
    }

    debug("copying %d bytes", exp_bytes);
    if (output != NULL)
      memcpy(output, obufrest, exp_bytes);

    free(obufrest);

    for (i = 0; i < exp_bytes; i++) {
      uint8_t r = (uint8_t) obufrest[i];

      c = 0;
      while (c < 8) {
        if (r & 1) {
          (*p)++;
        } else {
          (*f)++;
        }

        r >>= 1;
        c++;

        if ((*p) + (*f) >= total_coins)
          break;
      }
    }
  }

  close(sock);



  return STATUS_SUCCESS;
}
