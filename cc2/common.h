/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium 
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : common.h
#   Last Modified : 2023-07-20 12:43
#   Describe      : 
#
# ====================================================*/

#ifndef  _CC2_COMMON_H
#define  _CC2_COMMON_H


int init_cc2_socket();
char *alloc_cc2_packet(int);
int cc2_detect(unsigned char *, int, int *, int *, unsigned char *);
int cc2_delete(unsigned char *, unsigned char *, int);

//#define CC2_UNIX_SOCKET_PATH "/opt/raida/unix.sock"
#define CC2_UNIX_SOCKET_PATH "/opt/superraida/unix.sock"

#endif // _CC2_COMMON_H


