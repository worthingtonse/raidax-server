/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : net.h
#   Last Modified : 2025-07-29 12:20
#   Describe      : Network header with UDP performance optimizations
#                 ** FIXED linker error by adding close_connection prototype. **
#
# ====================================================*/

#ifndef _NET_H
#define _NET_H

#include "protocol.h"

// In seconds
#define RAIDA_EPOLL_TIMEOUT 10000

// How many evens epoll can have in its backlog
#define MAXEPOLLSIZE 10000

// Maximum file descriptors to handle
#define MAX_FDS 65535

// Maximum allowed body size for a request to prevent memory exhaustion attacks.
#define MAX_BODY_SIZE 65536 // 64KB

// SOCKET read timeout in seconds
#define SOCKET_TIMEOUT 2

//  Variable header size constants
#define REQUEST_HEADER_SIZE_MIN 32  // Minimum header size (Type 0/1/2)
#define REQUEST_HEADER_SIZE_MAX 48  // Maximum header size (Type 4/5)
#define RESPONSE_HEADER_SIZE_MIN 32 // Minimum response size (Type 0/1/2)
#define RESPONSE_HEADER_SIZE_MAX 48 // Maximum response size (Type 4/5)

// Keep legacy constant for compatibility, but use max size
#ifndef REQUEST_HEADER_SIZE
#define REQUEST_HEADER_SIZE REQUEST_HEADER_SIZE_MAX
#endif
#ifndef RESPONSE_HEADER_SIZE
#define RESPONSE_HEADER_SIZE RESPONSE_HEADER_SIZE_MAX
#endif

int init_and_listen_sockets(void);

int init_tcp_socket(void);
int init_udp_socket(void);

//  Function to initialize the UDP connection info object pool **
int init_udp_ci_pool(void);

int set_nonblocking(int);
int set_blocking(int);

conn_info_t *alloc_ci(int sk);
void free_ci(conn_info_t *ci);

// Functions to handle different stages of a connection
void handle_new_tcp_connection(int tsocket);
void handle_udp_request(int usocket);
void handle_connection_event(conn_info_t *ci, uint32_t events);

void arm_socket_for_write(conn_info_t *ci);

// ** NEW: Make close_connection visible to other files **
void close_connection(conn_info_t *ci);

int get_header_size_for_encryption_type(int encryption_type);

#endif // _NET_H
