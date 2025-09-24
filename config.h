/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : config.h
#   Last Modified : 2025-07-18 13:30
#   Describe      : Configuration header with synchronization switch
#
# ====================================================*/

#ifndef _CONFIG_H
#define _CONFIG_H

#include <limits.h>
#include "protocol.h"

// Default configuration values
#define DEFAULT_FLUSH_FREQ 300
#define DEFAULT_INTEGRITY_FREQ 3600
#define DEFAULT_UDP_PAYLOAD_THRESHOLD 1024

// Function declarations
int read_config(char *binary_path);

/* * Main configuration structure
 * It is global and can be read from multiple threads
 * It is written only once when the program starts
 *
 */
struct config_s
{
  // This RAIDA number
  int raida_no;

  // Port to listen
  int port;

  // How often we synchronize memory with the disk
  int flush_freq;

  // How often we check integrity
  int integrity_freq;

  // ** NEW: Master switch for the Merkle Tree integrity system **
  // This allows the feature to be deployed but kept disabled until all servers are updated.
  int synchronization_enabled;

  // UDP payload
  int udp_payload_threshold;

  // Current working directory
  char *cwd;

  // Admin key for executive commands
  unsigned char admin_key[16];

  // Neighbour RAIDA servers
  char *raida_servers[TOTAL_RAIDA_SERVERS];
  uint16_t raida_servers_ports[TOTAL_RAIDA_SERVERS];

  // Binary converted
  struct sockaddr *raida_addrs[TOTAL_RAIDA_SERVERS];

  // coin ID that this RAIDA server is managing
  uint8_t coin_id;

  // number of threads in the thread pool
  uint8_t threads;

  // proxy server
  char *proxy_addr;
  int proxy_port;

  // Proxy key for executive commands
  unsigned char proxy_key[16];

  // Number of blockchain confirmations for BTC
  uint8_t btc_confirmations;
};

// The name of the main configuration file
// It is located in the same directory as the binary
#define CONFIG_FILE_NAME "config.toml"

// ** SECURITY FIX: Removed hardcoded ADMIN_KEY macro. **
// The admin_key MUST now be set in the config.toml file.

// ** SECURITY FIX: Removed hardcoded DEFAULT_PROXY_KEY macro. **
// The proxy_key MUST now be set in the config.toml file.

#define DEFAULT_PROXY_PORT 50000
#define DEFAULT_PROXY_ADDR "swap.cloudcoin.org"

#endif // _CONFIG_H
