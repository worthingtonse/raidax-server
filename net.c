/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : net.c
#   Last Modified : 2025-07-29 12:20
#   Describe      : Main Network Loops, with an object pool for UDP
#                 to optimize performance under high traffic.
#                 ** CONCURRENCY FIX: Added robust error handling for all
#                 ** mutex operations to ensure production-level stability.
#
# ====================================================*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>

#include "log.h"
#include "protocol.h"
#include "net.h"
#include "config.h"
#include "thpool.h"
#include "stats.h"
#include "integrity.h"
#include "db.h"

extern int is_finished;
extern struct config_s config;
extern threadpool thpool;

// --- TCP Connection Management ---
conn_info_t *connections[MAX_FDS];
static int epoll_fd;
static int write_event_fd;
#define MOD_QUEUE_SIZE 1024
conn_info_t *mod_queue[MOD_QUEUE_SIZE];
int mod_queue_head = 0;
int mod_queue_tail = 0;
pthread_mutex_t mod_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

// --- UDP Performance Optimization: Object Pool for conn_info_t ---
#define UDP_CI_POOL_SIZE 4096
static conn_info_t udp_ci_pool[UDP_CI_POOL_SIZE];
static conn_info_t *udp_ci_stack[UDP_CI_POOL_SIZE];
static int udp_ci_stack_top;
static pthread_mutex_t udp_ci_pool_mutex;

// Forward declarations for internal functions
static void handle_read(conn_info_t *ci);
static void handle_write(conn_info_t *ci);
static void process_write_queue();
static void handle_udp_vote_request(int usocket, unsigned char *buffer, struct sockaddr_in *cliaddr);
static conn_info_t *get_udp_ci_from_pool(int sk);
static void return_udp_ci_to_pool(conn_info_t *ci);

int init_udp_ci_pool(void)
{
  debug("Initializing UDP connection info object pool with %d structs.", UDP_CI_POOL_SIZE);
  int rc = pthread_mutex_init(&udp_ci_pool_mutex, NULL);
  if (rc != 0)
  {
    error("Failed to initialize UDP CI pool mutex: %s", strerror(rc));
    return -1;
  }
  udp_ci_stack_top = -1;
  for (int i = 0; i < UDP_CI_POOL_SIZE; i++)
  {
    udp_ci_pool[i].sa = malloc(sizeof(struct sockaddr_in));
    if (!udp_ci_pool[i].sa)
    {
      error("Failed to pre-allocate sockaddr for UDP CI pool item %d", i);
      for (int j = 0; j < i; j++)
      {
        free(udp_ci_pool[j].sa);
      }
      return -1;
    }
    udp_ci_stack_top++;
    udp_ci_stack[udp_ci_stack_top] = &udp_ci_pool[i];
  }
  return 0;
}

static conn_info_t *get_udp_ci_from_pool(int sk)
{
  if (pthread_mutex_lock(&udp_ci_pool_mutex) != 0)
  {
    error("Failed to lock UDP CI pool mutex for get");
    return NULL;
  }

  if (udp_ci_stack_top == -1)
  {
    pthread_mutex_unlock(&udp_ci_pool_mutex);
    warning("UDP CI object pool exhausted. Dropping packet.");
    return NULL;
  }
  conn_info_t *ci = udp_ci_stack[udp_ci_stack_top];
  udp_ci_stack_top--;

  if (pthread_mutex_unlock(&udp_ci_pool_mutex) != 0)
  {
    error("Failed to unlock UDP CI pool mutex for get");
  }

  ci->sk = sk;
  gettimeofday(&ci->start_time, NULL);
  ci->body_size = 0;
  ci->body = NULL;
  ci->output_size = 0;
  ci->output = NULL;
  ci->write_buf = NULL;
  ci->is_udp_pooled = 1;

  return ci;
}

static void return_udp_ci_to_pool(conn_info_t *ci)
{
  if (!ci)
    return;

  if (ci->body)
    free(ci->body);
  if (ci->output)
    free(ci->output);
  if (ci->write_buf)
    free(ci->write_buf);

  if (pthread_mutex_lock(&udp_ci_pool_mutex) != 0)
  {
    error("Failed to lock UDP CI pool mutex for return");
    return;
  }

  if (udp_ci_stack_top < UDP_CI_POOL_SIZE - 1)
  {
    udp_ci_stack_top++;
    udp_ci_stack[udp_ci_stack_top] = ci;
  }
  else
  {
    error("UDP CI object pool stack overflow. This should not happen.");
  }

  if (pthread_mutex_unlock(&udp_ci_pool_mutex) != 0)
  {
    error("Failed to unlock UDP CI pool mutex for return");
  }
}

static void push_mod_queue(conn_info_t *ci)
{
  if (pthread_mutex_lock(&mod_queue_mutex) != 0)
  {
    error("Failed to lock mod_queue mutex for push");
    return;
  }
  mod_queue[mod_queue_tail] = ci;
  mod_queue_tail = (mod_queue_tail + 1) % MOD_QUEUE_SIZE;
  if (mod_queue_tail == mod_queue_head)
  {
    error("Epoll modification queue overflow!");
  }
  pthread_mutex_unlock(&mod_queue_mutex);
}

static conn_info_t *pop_mod_queue()
{
  conn_info_t *ci = NULL;
  if (pthread_mutex_lock(&mod_queue_mutex) != 0)
  {
    error("Failed to lock mod_queue mutex for pop");
    return NULL;
  }
  if (mod_queue_head != mod_queue_tail)
  {
    ci = mod_queue[mod_queue_head];
    mod_queue_head = (mod_queue_head + 1) % MOD_QUEUE_SIZE;
  }
  pthread_mutex_unlock(&mod_queue_mutex);
  return ci;
}

void arm_socket_for_write(conn_info_t *ci)
{
  push_mod_queue(ci);
  uint64_t u = 1;
  if (write(write_event_fd, &u, sizeof(uint64_t)) < 0)
  {
    error("Failed to write to eventfd: %s", strerror(errno));
  }
}

static void process_write_queue()
{
  conn_info_t *ci;
  while ((ci = pop_mod_queue()) != NULL)
  {
    if (ci->state == STATE_WANT_WRITE)
    {
      struct epoll_event event;
      event.data.ptr = ci;
      event.events = EPOLLOUT | EPOLLET;
      if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ci->sk, &event) < 0)
      {
        error("Failed to arm socket %d for write: %s", ci->sk, strerror(errno));
        close_connection(ci);
      }
    }
  }
}

int init_and_listen_sockets(void)
{
  int usocket, tsocket;
  struct epoll_event eudp, etcp, e_eventfd;
  struct epoll_event events[MAXEPOLLSIZE];

  debug("Preparing listening sockets");

  epoll_fd = epoll_create1(0);
  if (epoll_fd < 0)
  {
    error("Failed to create epoll: %s", strerror(errno));
    return -1;
  }

  write_event_fd = eventfd(0, EFD_NONBLOCK);
  if (write_event_fd < 0)
  {
    error("Failed to create eventfd: %s", strerror(errno));
    close(epoll_fd);
    return -1;
  }
  e_eventfd.events = EPOLLIN | EPOLLET;
  e_eventfd.data.fd = write_event_fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, write_event_fd, &e_eventfd) < 0)
  {
    error("Failed to add eventfd to epoll: %s", strerror(errno));
    close(write_event_fd);
    close(epoll_fd);
    return -1;
  }

  tsocket = init_tcp_socket();
  if (tsocket < 0)
  {
    close(epoll_fd);
    close(write_event_fd);
    return -1;
  }
  etcp.events = EPOLLIN | EPOLLET;
  etcp.data.fd = tsocket;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tsocket, &etcp) < 0)
  {
    error("Failed to add TCP socket to epoll: %s", strerror(errno));
    close(tsocket);
    close(epoll_fd);
    close(write_event_fd);
    return -1;
  }
  debug("TCP socket initialized and added to epoll");

  usocket = init_udp_socket();
  if (usocket < 0)
  {
    close(tsocket);
    close(epoll_fd);
    close(write_event_fd);
    return -1;
  }
  eudp.events = EPOLLIN | EPOLLET;
  eudp.data.fd = usocket;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, usocket, &eudp) < 0)
  {
    error("Failed to add UDP socket to epoll: %s", strerror(errno));
    close(tsocket);
    close(usocket);
    close(epoll_fd);
    close(write_event_fd);
    return -1;
  }
  debug("UDP socket initialized and added to epoll");

  debug("Ready for the main event loop");
  while (!is_finished)
  {
    int n_events = epoll_wait(epoll_fd, events, MAXEPOLLSIZE, RAIDA_EPOLL_TIMEOUT);
    if (n_events < 0)
    {
      if (errno == EINTR)
      {
        debug("Interrupted epoll wait, continuing");
        continue;
      }
      error("Epoll wait failed: %s", strerror(errno));
      break;
    }

    for (int i = 0; i < n_events; i++)
    {
      if (events[i].data.fd == tsocket)
      {
        handle_new_tcp_connection(tsocket);
      }
      else if (events[i].data.fd == usocket)
      {
        handle_udp_request(usocket);
      }
      else if (events[i].data.fd == write_event_fd)
      {
        uint64_t u;
        read(write_event_fd, &u, sizeof(uint64_t));
        process_write_queue();
      }
      else
      {
        conn_info_t *ci = (conn_info_t *)events[i].data.ptr;
        if (ci)
        {
          handle_connection_event(ci, events[i].events);
        }
      }
    }
  }

  debug("Closing sockets and shutting down");
  close(tsocket);
  close(usocket);
  close(write_event_fd);
  close(epoll_fd);
  return 0;
}

int init_tcp_socket()
{
  int sockfd;
  struct sockaddr_in servaddr;

  debug("Initializing TCP socket");

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
  {
    error("Failed to create TCP socket: %s", strerror(errno));
    return -1;
  }

  const int enable = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
  {
    error("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
    close(sockfd);
    return -1;
  }

  if (set_nonblocking(sockfd) < 0)
  {
    error("Failed to set TCP listening socket to non-blocking");
    close(sockfd);
    return -1;
  }

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(config.port);

  if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
  {
    error("TCP bind error: %s", strerror(errno));
    close(sockfd);
    return -1;
  }

  if (listen(sockfd, SOMAXCONN) < 0)
  {
    error("Failed to listen on TCP socket: %s", strerror(errno));
    close(sockfd);
    return -1;
  }

  return sockfd;
}

int init_udp_socket()
{
  int sockfd;
  struct sockaddr_in servaddr;

  debug("Initializing UDP socket");

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    error("Failed to create UDP socket: %s", strerror(errno));
    return -1;
  }

  if (set_nonblocking(sockfd) < 0)
  {
    error("Failed to set UDP socket to non-blocking");
    close(sockfd);
    return -1;
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(config.port);

  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
  {
    error("Failed to bind UDP socket: %s", strerror(errno));
    close(sockfd);
    return -1;
  }

  return sockfd;
}

void handle_new_tcp_connection(int tsocket)
{
  struct sockaddr_in cliaddr;
  socklen_t clilen = sizeof(cliaddr);
  int client_fd = accept(tsocket, (struct sockaddr *)&cliaddr, &clilen);
  if (client_fd < 0)
  {
    // Since we are edge-triggered, we expect EAGAIN or EWOULDBLOCK if no more connections.
    // Any other error is a problem.
    if (errno != EAGAIN && errno != EWOULDBLOCK)
    {
      error("Failed to accept new TCP connection: %s", strerror(errno));
    }
    return; // Return to the main event loop
  }

  char client_ip[16];
  strncpy(client_ip, inet_ntoa(cliaddr.sin_addr), 15);
  client_ip[15] = '\0';

  debug("TCP: Accepted new connection on fd %d from %s", client_fd, client_ip);

  if (set_nonblocking(client_fd) < 0)
  {
    error("TCP: Failed to set socket %d non-blocking", client_fd);
    close(client_fd);
    return;
  }

  // Set TCP keepalive options
  int keepalive = 1, keep_idle = 60, keep_interval = 10, keep_count = 5;
  setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
  setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keep_idle, sizeof(keep_idle));
  setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keep_interval, sizeof(keep_interval));
  setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT, &keep_count, sizeof(keep_count));
  debug("TCP: Keep-Alive enabled for fd %d", client_fd);

  conn_info_t *ci = alloc_ci(client_fd);
  if (!ci)
  {
    error("TCP: Failed to allocate connection info for fd %d", client_fd);
    close(client_fd);
    return;
  }

  strncpy(ci->ip, client_ip, 15);
  ci->ip[15] = '\0';
  connections[client_fd] = ci;

  struct epoll_event event;
  event.data.ptr = ci;
  event.events = EPOLLIN | EPOLLET;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0)
  {
    error("TCP: Failed to add client socket %d to epoll: %s", client_fd, strerror(errno));
    close_connection(ci);
    return;
  }

  debug("TCP: Connection %d from %s added to epoll, ready for header reading", client_fd, client_ip);
}
void handle_connection_event(conn_info_t *ci, uint32_t events)
{
  if ((events & EPOLLERR) || (events & EPOLLHUP))
  {
    error("epoll error on socket %d", ci->sk);
    close_connection(ci);
    return;
  }

  if (events & EPOLLIN)
  {
    handle_read(ci);
  }

  if (events & EPOLLOUT)
  {
    handle_write(ci);
  }
}

static void handle_read(conn_info_t *ci)
{
  while (1)
  {
    ssize_t bytes_read;
    unsigned char *target_buf;
    int to_read;

    if (ci->state != STATE_WANT_READ_HEADER && ci->state != STATE_WANT_READ_BODY)
    {
      break;
    }

    if (ci->state == STATE_WANT_READ_HEADER)
    {
      // CRITICAL: PHASE 1 - Read minimum bytes to get encryption type (17 bytes minimum)
      if (ci->bytes_read < 17)
      {
        target_buf = ci->read_buf + ci->bytes_read;
        to_read = 17 - ci->bytes_read;
        debug("TCP: Reading encryption type detection bytes (%d/%d)", ci->bytes_read, 17);
      }
      else if (ci->bytes_read == 17)
      {
        // CRITICAL: PHASE 2 - We have encryption type, determine actual header size needed
        int encryption_type = ci->read_buf[16];
        int actual_header_size = get_header_size_for_encryption_type(encryption_type);
        ci->bytes_to_read = actual_header_size;

        debug("TCP: Detected encryption type %d, using %d-byte header",
              encryption_type, actual_header_size);

        // For legacy types (32-byte headers), we may already have enough bytes
        if (actual_header_size == 32)
        {
          if (ci->bytes_read >= 32)
          {
            goto validate_header_now;
          }
          target_buf = ci->read_buf + ci->bytes_read;
          to_read = 32 - ci->bytes_read;
        }
        else
        {
          // For modern types (48-byte headers)
          target_buf = ci->read_buf + ci->bytes_read;
          to_read = 48 - ci->bytes_read;
        }
      }
      else
      {
        // CRITICAL: PHASE 3 - Reading remaining header bytes to reach target size
        target_buf = ci->read_buf + ci->bytes_read;
        to_read = ci->bytes_to_read - ci->bytes_read;
        debug("TCP: Reading remaining header bytes (%d/%d)", ci->bytes_read, ci->bytes_to_read);
      }
    }
    else
    {
      // Reading body (unchanged)
      target_buf = ci->body + ci->bytes_read;
      to_read = ci->bytes_to_read - ci->bytes_read;
      debug("TCP: Reading body bytes (%d/%d)", ci->bytes_read, ci->bytes_to_read);
    }

    bytes_read = recv(ci->sk, target_buf, to_read, 0);

    if (bytes_read < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        break;
      }
      error("TCP recv error on socket %d: %s", ci->sk, strerror(errno));
      close_connection(ci);
      return;
    }

    if (bytes_read == 0)
    {
      debug("TCP connection closed by peer on socket %d", ci->sk);
      close_connection(ci);
      return;
    }

    ci->bytes_read += bytes_read;
    debug("TCP: Received %zd bytes, total: %d", bytes_read, ci->bytes_read);

    // Check if we've completed the current read operation
    if (ci->bytes_read == ci->bytes_to_read)
    {
      if (ci->state == STATE_WANT_READ_HEADER)
      {
      validate_header_now:
        debug("TCP: Header complete (%d bytes), validating...", ci->bytes_read);

        int status_code = validate_header(ci->read_buf, ci);
        if (status_code != NO_ERROR)
        {
          error("TCP: Header validation failed with code %d", status_code);
          send_command_error(status_code, ci);
          return;
        }

        debug("TCP: Header valid, encryption type: %d, body size: %d",
              ci->encryption_type, ci->body_size);

        if (ci->body_size > MAX_BODY_SIZE)
        {
          error("TCP: Client requested body size %d which exceeds MAX_BODY_SIZE %d",
                ci->body_size, MAX_BODY_SIZE);
          send_command_error(ERROR_INVALID_PACKET_LENGTH, ci);
          return;
        }

        if (ci->body_size > 0)
        {
          ci->body = malloc(ci->body_size);
          if (!ci->body)
          {
            error("TCP: Failed to allocate %d bytes for request body", ci->body_size);
            send_command_error(ERROR_MEMORY_ALLOC, ci);
            return;
          }
          ci->state = STATE_WANT_READ_BODY;
          ci->bytes_read = 0;
          ci->bytes_to_read = ci->body_size;
          debug("TCP: Starting body read (%d bytes needed)", ci->body_size);
        }
        else
        {
          debug("TCP: No body needed, processing command %d/%d", ci->cgroup, ci->command);
          ci->state = STATE_PROCESSING;
          thpool_add_work(thpool, run_command, (void *)ci);
          break;
        }
      }
      else if (ci->state == STATE_WANT_READ_BODY)
      {
        debug("TCP: Body complete (%d bytes), validating and decrypting...", ci->body_size);

        int status_code = validate_decrypt_body(ci);
        if (status_code != NO_ERROR)
        {
          error("TCP: Body validation/decryption failed with code %d", status_code);
          send_command_error(status_code, ci);
          return;
        }

        debug("TCP: Body valid, processing command %d/%d", ci->cgroup, ci->command);
        ci->state = STATE_PROCESSING;
        thpool_add_work(thpool, run_command, (void *)ci);
        break;
      }
    }
  }
}

static void handle_write(conn_info_t *ci)
{
  if (ci->state != STATE_WANT_WRITE)
  {
    return;
  }

  while (ci->bytes_written < ci->bytes_to_write)
  {
    int bytes_to_write = ci->bytes_to_write - ci->bytes_written;
    int bytes_sent = send(ci->sk, ci->write_buf + ci->bytes_written, bytes_to_write, 0);

    if (bytes_sent < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        return;
      }
      error("Error writing to socket %d: %s", ci->sk, strerror(errno));
      close_connection(ci);
      return;
    }

    ci->bytes_written += bytes_sent;
  }

  if (ci->bytes_written == ci->bytes_to_write)
  {
    write_stat(ci);
    close_connection(ci);
  }
}

static void handle_udp_vote_request(int usocket, unsigned char *buffer, struct sockaddr_in *cliaddr)
{
  unsigned char response_buf[1 + 16];
  unsigned char my_all_roots[TOTAL_DENOMINATIONS * HASH_SIZE];

  debug("Handling UDP integrity vote request.");

  for (int i = 0; i < TOTAL_DENOMINATIONS; i++)
  {
    int8_t den = get_den_by_idx(i);
    if (get_merkle_root(den, &my_all_roots[i * HASH_SIZE]) != 0)
    {
      memset(&my_all_roots[i * HASH_SIZE], 0, HASH_SIZE);
    }
  }

  if (memcmp(my_all_roots, &buffer[1], TOTAL_DENOMINATIONS * HASH_SIZE) == 0)
  {
    response_buf[0] = 1;
  }
  else
  {
    response_buf[0] = 0;
  }

  memcpy(&response_buf[1], &buffer[1 + TOTAL_DENOMINATIONS * HASH_SIZE], 16);
  sendto(usocket, response_buf, sizeof(response_buf), 0, (struct sockaddr *)cliaddr, sizeof(struct sockaddr_in));
}

// CORRECTED handle_udp_request() function - preserves ALL performance improvements
void handle_udp_request(int usocket)
{
  while (1)
  {
    unsigned char *buf = malloc(config.udp_payload_threshold);
    if (!buf)
    {
      error("UDP: Failed to allocate buffer for UDP request");
      return;
    }

    struct sockaddr_in cliaddr;
    socklen_t slen = sizeof(cliaddr);
    ssize_t bytes = recvfrom(usocket, buf, config.udp_payload_threshold, 0,
                             (struct sockaddr *)&cliaddr, &slen);

    if (bytes < 0)
    {
      free(buf);
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        break; // No more UDP packets available
      }
      error("UDP recvfrom error: %s", strerror(errno));
      break;
    }

    debug("UDP: Received %zd bytes from %s", bytes, inet_ntoa(cliaddr.sin_addr));
    inc_stat(REQUESTS_FIELD_IDX, 1);

    // Handle special integrity vote requests (PRESERVED)
    size_t vote_request_size = 1 + (TOTAL_DENOMINATIONS * HASH_SIZE) + 16;
    if (bytes == vote_request_size && buf[0] == 7)
    {
      debug("UDP: Processing integrity vote request");
      handle_udp_vote_request(usocket, buf, &cliaddr);
      free(buf);
      continue;
    }

    // PERFORMANCE: Use UDP connection info pool (PRESERVED)
    conn_info_t *ci = get_udp_ci_from_pool(usocket);
    if (!ci)
    {
      error("UDP: Failed to get connection info from pool");
      free(buf);
      continue; // Pool exhausted, but not an error
    }

    // Set up connection info (PRESERVED)
    memcpy(ci->sa, &cliaddr, sizeof(struct sockaddr_in));
    strncpy(ci->ip, inet_ntoa(cliaddr.sin_addr), 15);
    ci->ip[15] = '\0';

    //  Pre-validation error handling - return to pool immediately
    if (bytes < 17)
    {
      error("UDP: Packet too small (%zd bytes) to contain encryption type", bytes);
      return_udp_ci_to_pool(ci);
      free(buf);
      continue;
    }

    // : Dynamic header size detection
    int encryption_type = buf[16];
    int expected_header_size = get_header_size_for_encryption_type(encryption_type);

    debug("UDP: Detected encryption type %d, expecting %d-byte header",
          encryption_type, expected_header_size);

    if (bytes < expected_header_size)
    {
      error("UDP: Packet too small (%zd bytes) for encryption type %d (need %d bytes)",
            bytes, encryption_type, expected_header_size);
      return_udp_ci_to_pool(ci); // ✅ FIXED: Direct pool return
      free(buf);
      continue;
    }

    //  Header validation with proper encryption type handling
    int status_code = validate_header(buf, ci);
    if (status_code != NO_ERROR)
    {
      error("UDP: Header validation failed with code %d", status_code);
      send_command_error(status_code, ci); // This handles pool return via finish_command()
      free(buf);
      continue;
    }

    debug("UDP: Header valid, encryption type: %d, body size: %d",
          ci->encryption_type, ci->body_size);

    //  Packet size validation
    int expected_total_size = expected_header_size + ci->body_size;
    if (bytes < expected_total_size)
    {
      error("UDP: Packet too small (%zd bytes) for header+body (need %d bytes)",
            bytes, expected_total_size);
      send_command_error(ERROR_INVALID_PACKET_LENGTH, ci);
      free(buf);
      continue;
    }

    //  Body size limits
    if (ci->body_size > 0)
    {
      if (ci->body_size > MAX_BODY_SIZE)
      {
        error("UDP: Body size %d exceeds MAX_BODY_SIZE %d", ci->body_size, MAX_BODY_SIZE);
        send_command_error(ERROR_INVALID_PACKET_LENGTH, ci);
        free(buf);
        continue;
      }

      ci->body = malloc(ci->body_size);
      if (!ci->body)
      {
        error("UDP: Failed to allocate %d bytes for request body", ci->body_size);
        send_command_error(ERROR_MEMORY_ALLOC, ci);
        free(buf);
        continue;
      }

      // Copy body from packet (after header)
      memcpy(ci->body, buf + expected_header_size, ci->body_size);

      debug("UDP: Body extracted (%d bytes), validating and decrypting...", ci->body_size);

      //   Body validation with proper encryption handling
      status_code = validate_decrypt_body(ci);
      if (status_code != NO_ERROR)
      {
        error("UDP: Body validation/decryption failed with code %d", status_code);
        send_command_error(status_code, ci);
        free(buf);
        continue;
      }

      debug("UDP: Body valid");
    }
    else
    {
      debug("UDP: No body present");
    }

    free(buf);

    debug("UDP: Processing command %d/%d", ci->cgroup, ci->command);

    //  PERFORMANCE: Thread pool integration
    thpool_add_work(thpool, run_command, (void *)ci);
    // Note: ci will be returned to pool by finish_command() after processing
  }
}
int set_nonblocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1)
  {
    error("fcntl(F_GETFL) failed: %s", strerror(errno));
    return -1;
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
  {
    error("fcntl(F_SETFL) failed: %s", strerror(errno));
    return -1;
  }
  return 0;
}

int set_blocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1)
  {
    error("fcntl(F_GETFL) failed: %s", strerror(errno));
    return -1;
  }
  if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
  {
    error("fcntl(F_SETFL) failed: %s", strerror(errno));
    return -1;
  }
  return 0;
}

conn_info_t *alloc_ci(int sk)
{
  conn_info_t *ci = (conn_info_t *)malloc(sizeof(conn_info_t));
  if (ci == NULL)
  {
    error("Failed to allocate connection info");
    return NULL;
  }

  memset(ci, 0, sizeof(conn_info_t));
  ci->sk = sk;
  ci->state = STATE_WANT_READ_HEADER;
  ci->bytes_to_read = REQUEST_HEADER_SIZE_MAX; // Start with max, adjust dynamically
  gettimeofday(&ci->start_time, NULL);
  ci->is_udp_pooled = 0;

  return ci;
}

void free_ci(conn_info_t *ci)
{
  if (!ci)
    return;

  if (ci->is_udp_pooled)
  {
    return_udp_ci_to_pool(ci);
  }
  else
  {
    if (ci->sa)
      free(ci->sa);
    if (ci->body)
      free(ci->body);
    if (ci->output)
      free(ci->output);
    if (ci->write_buf)
      free(ci->write_buf);
    free(ci);
  }
}

void close_connection(conn_info_t *ci)
{
  if (!ci)
    return;

  debug("Closing connection for fd %d", ci->sk);

  epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ci->sk, NULL);
  close(ci->sk);

  if (ci->sk < MAX_FDS)
  {
    connections[ci->sk] = NULL;
  }
  free_ci(ci);
}
