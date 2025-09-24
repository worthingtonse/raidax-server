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
int cc2_delete(unsigned char *an, unsigned char *snsbuf, int total_coins) {
  int rv;
  unsigned char tan[32];
  unsigned char pg[16];
  unsigned char *can;
  uint32_t sn;
  int i;
  int sock;
  char *buf, obuf[12], *obufrest;
  uint8_t status;
  uint16_t rbl;
  int exp_bytes, c;


  // 3SN + 1ZEROBYTE + 16PG + 16AN
  buf = alloc_cc2_packet(total_coins * 3 + 33);
  if (buf == NULL) {
    error("Failed to allocate CC2 packet");
    return ERROR_LEGACY_DB;
  }

  debug("Deleting %d cc2 coins", total_coins);

  // Hash Delete
  buf[5] = 0x36;

  sock = init_cc2_socket();
  if (sock < 0) {
    error("Failed to connect to UNIX socket");
    return ERROR_LEGACY_DB;
  }

  memset(pg, 0, 16);

  // zero range sns
  buf[22 + 16] = 0;

  for (i = 0; i < total_coins; i++) {
    sn = get_sn(&snsbuf[i * 5 + 1]);
    debug("SN %d ", sn);

    // SN
    buf[22 + 16 + i * 3 + 1] = (sn >> 16) & 0xff;
    buf[22 + 16 + i * 3 + 2] = (sn >> 8) & 0xff;
    buf[22 + 16 + i * 3 + 3] = sn & 0xff;
  }

  debug("i=%d",i);

  // AN
  memcpy(buf + 22 + 16 + i * 3 + 1, an, 16); 

  // PG
  memcpy(buf + 22 + 16 + i * 3 + 1 + 16, pg, 16); 

  debug("Launching hash delete");

  debug("Sending length %d", 22 + 16 + total_coins * 3 + 33 + 2);

  rv = send(sock, buf, 22 + 16 + total_coins * 3 + 33 + 2, 0);
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
  close(sock);

  debug("RAIDA replied with %u", status);

  if (status == 242) {
    error("Failed to delete. All coins are counterfeit");
    return STATUS_ALL_FAIL;
  }

  if (status == 243) {
    error("Failed to delete. Some coins are counterfeit");
    return STATUS_MIXED;
  } 

  if (status != 241) {
    error("Failed to delete");
    return ERROR_LEGACY_DB;
  } 
  
  
  
  debug("Successfully deleted");

  return STATUS_SUCCESS;
}
