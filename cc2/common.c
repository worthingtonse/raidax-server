/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium 
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : common.c
#   Last Modified : 2023-07-20 14:49
#   Describe      : 
#
# ====================================================*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/un.h>

#include "../log.h"
#include "../protocol.h"
#include "../config.h"
#include "../utils.h"
#include "common.h"

extern struct config_s config;

int init_cc2_socket() {
  struct sockaddr_un server_sockaddr; 
  struct timeval timeout;      
  int sock, rv, len;
  char buf[256];

  debug("Connecting to UNIX socket");

  memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
     
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) {
    error("Failed to create UNIX socket: %s", strerror(errno));
    return -1;
  }

  timeout.tv_sec = 6;
  timeout.tv_usec = 0;
    
  rv = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
  if (rv < 0) {
    error("Failed to set socket timeout: %s", strerror(errno));
    return -1;
  }

  server_sockaddr.sun_family = AF_UNIX;
  strcpy(server_sockaddr.sun_path, CC2_UNIX_SOCKET_PATH);
  rv = connect(sock, (struct sockaddr *) &server_sockaddr, sizeof(struct sockaddr_un));
  if (rv < 0) {
    error("Failed to connect to CC2 Unix socket: %s", strerror(errno));
    close(sock);
    return -1;
  }

  return sock;
}

char *alloc_cc2_packet(int length) {
  char *buf;
  int len, i, blen;
  uint8_t c0, c1, c2, c3;
  unsigned int crc;

  // 22 header size + 2 EOF + 16CH
  len = 22 + 2 + 16 + length;
  buf = (char *) malloc(len);
  if (buf == NULL)
    return NULL;

  
  for (i = 0; i < 16; i++) {
    buf[22 + i] = 0x10;
  }

  crc = crc32b(&buf[22], 12);

  buf[22 + 12] = (crc >> 24) & 0xff;
  buf[22 + 13] = (crc >> 16) & 0xff;
  buf[22 + 14] = (crc >> 8) & 0xff;
  buf[22 + 15] = (crc) & 0xff;


  blen = len - 22;

  buf[len - 1] = 0x3e;
  buf[len - 2] = 0x3e;

  buf[0] = 0; // CloudID
  buf[1] = 0; // SplitID
  buf[2] = config.raida_no; // RaidaID
  buf[3] = 0; // ShardID (does not matter for CC2)
  buf[4] = 0; // CMD0
  buf[5] = 1; // CMD1 Detect
  buf[6] = c3; // CheckSum
  buf[7] = 0; // CoinID
  buf[8] = 1; // CoinID
  buf[9] = 0;
  buf[10] = 0;
  buf[11] = 0;
  buf[12] = 0x11; // Echo
  buf[13] = 0x11;
  buf[14] = (blen >> 8) & 0xff;
  buf[15] = blen & 0xff;
  buf[16] = 0; // No encryption
  buf[17] = 0;
  buf[18] = 0;
  buf[19] = 0;
  buf[20] = 0;
  buf[21] = 0;

  return buf;
}
