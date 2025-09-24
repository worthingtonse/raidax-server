/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : config.c
#   Last Modified : 2025-07-18 13:32
#   Describe      : Main configuration file processing with synchronization switch
#
# ====================================================*/

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "main.h"
#include "toml.h"
#include "config.h"
#include "utils.h"

struct config_s config;
void dump_config(void);

/*
 * Read the TOML config file that must exist in the same folder as the binary
 *
 * binary_path - path to this binary
 *
 */
int read_config(char *binary_path)
{
  int i, rv;
  char *pos, *tp;
  char config_path[PATH_MAX];
  char toml_error_buf[256];
  FILE *fp;
  struct hostent *he;
  struct addrinfo *res = NULL;
  struct addrinfo *ptr = NULL;
  struct addrinfo hints;
  int found = 0;
  char ipbuf[128];

  // Set default values first
  config.threads = 0;
  config.flush_freq = DEFAULT_FLUSH_FREQ;
  config.integrity_freq = DEFAULT_INTEGRITY_FREQ;
  config.udp_payload_threshold = DEFAULT_UDP_PAYLOAD_THRESHOLD;
  config.synchronization_enabled = 0; // Default to OFF

  config.cwd = dirname(binary_path);
  if (config.cwd == NULL)
  {
    error("Failed to get binary folder: %s", strerror(errno));
    return -1;
  }

  sprintf((char *)&config_path, "%s/%s", config.cwd, CONFIG_FILE_NAME);
  debug("Reading configuration file %s", config_path);

  fp = fopen(config_path, "r");
  if (!fp)
  {
    error("Failed to read raida config file %s: %s", config_path, strerror(errno));
    return -1;
  }

  toml_table_t *conf = toml_parse_file(fp, toml_error_buf, sizeof(toml_error_buf));
  if (!conf)
  {
    error("Failed to parse TOML config file: %s", toml_error_buf);
    fclose(fp);
    return -1;
  }

  fclose(fp);

  toml_table_t *server = toml_table_in(conf, "server");
  if (!server)
  {
    error("Failed to find [server] section in the config file");
    return -1;
  }

  // Mandatory: raida_id
  toml_datum_t raida_no = toml_int_in(server, "raida_id");
  if (!raida_no.ok)
  {
    error("Mandatory key 'raida_id' not found in config file");
    toml_free(conf);
    return -1;
  }

  // Mandatory: coin_id
  toml_datum_t coin_id = toml_int_in(server, "coin_id");
  if (!coin_id.ok)
  {
    error("Mandatory key 'coin_id' not found in config file");
    toml_free(conf);
    return -1;
  }

  // Mandatory: port
  toml_datum_t port = toml_int_in(server, "port");
  if (!port.ok)
  {
    error("Mandatory key 'port' not found in config file");
    toml_free(conf);
    return -1;
  }

  // Optional: threads
  toml_datum_t nthreads = toml_int_in(server, "threads");
  if (nthreads.ok)
  {
    config.threads = (uint8_t)nthreads.u.i;
  }

  // ** SECURITY FIX: 'proxy_key' is now mandatory. **
  toml_datum_t proxy_key = toml_string_in(server, "proxy_key");
  if (!proxy_key.ok)
  {
    error("Mandatory key 'proxy_key' not found in config file. Server will not start.");
    toml_free(conf);
    return -1;
  }
  if (strlen(proxy_key.u.s) != 32)
  {
    error("Invalid proxy_key length. Must be a 32-character hexadecimal string.");
    free(proxy_key.u.s);
    toml_free(conf);
    return -1;
  }
  pos = proxy_key.u.s;
  for (i = 0; i < 16; i++)
  {
    if (sscanf(pos, "%2hhx", &config.proxy_key[i]) != 1)
    {
      error("Failed to parse proxy_key. Must be a 32-character hexadecimal string.");
      free(proxy_key.u.s);
      toml_free(conf);
      return -1;
    }
    pos += 2;
  }
  free(proxy_key.u.s); // Free memory allocated by toml_string_in

  // ** SECURITY FIX: 'admin_key' is now mandatory. **
  toml_datum_t admin_key = toml_string_in(server, "admin_key");
  if (!admin_key.ok)
  {
    error("Mandatory key 'admin_key' not found in config file. Server will not start.");
    toml_free(conf);
    return -1;
  }
  if (strlen(admin_key.u.s) != 32)
  {
    error("Invalid admin_key length. Must be a 32-character hexadecimal string.");
    free(admin_key.u.s);
    toml_free(conf);
    return -1;
  }
  pos = admin_key.u.s;
  for (i = 0; i < 16; i++)
  {
    if (sscanf(pos, "%2hhx", &config.admin_key[i]) != 1)
    {
      error("Failed to parse admin_key. Must be a 32-character hexadecimal string.");
      free(admin_key.u.s);
      toml_free(conf);
      return -1;
    }
    pos += 2;
  }
  free(admin_key.u.s); // Free memory allocated by toml_string_in

  // Optional: proxy_addr, with default
  config.proxy_addr = DEFAULT_PROXY_ADDR;
  toml_datum_t proxy_addr = toml_string_in(server, "proxy_addr");
  if (proxy_addr.ok)
  {
    config.proxy_addr = proxy_addr.u.s; // Note: This memory is owned by toml-c, freed with toml_free
  }

  debug("Resolving proxy address: %s", config.proxy_addr);
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET; // Force IPv4 for simplicity, can be AF_UNSPEC
  hints.ai_socktype = SOCK_STREAM;

  rv = getaddrinfo(config.proxy_addr, NULL, &hints, &res);
  if (rv != 0)
  {
    error("Failed to resolve proxy host: %s -> %s", config.proxy_addr, gai_strerror(rv));
    toml_free(conf);
    return -1;
  }

  found = 0;
  for (ptr = res; ptr != NULL; ptr = ptr->ai_next)
  {
    if (ptr->ai_family == AF_INET)
    { // We only handle IPv4 for now
      config.proxy_addr = strdup(inet_ntoa(((struct sockaddr_in *)ptr->ai_addr)->sin_addr));
      found = 1;
      break;
    }
  }
  freeaddrinfo(res);
  if (!found)
  {
    error("Failed to find an IPv4 address for the proxy host.");
    toml_free(conf);
    return -1;
  }
  debug("Proxy IP resolved to %s", config.proxy_addr);

  // Optional: proxy_port, with default
  config.proxy_port = DEFAULT_PROXY_PORT;
  toml_datum_t proxy_port = toml_int_in(server, "proxy_port");
  if (proxy_port.ok)
  {
    config.proxy_port = (int)proxy_port.u.i;
  }

  // Optional: btc_confirmations, with default
  config.btc_confirmations = 2;
  toml_datum_t confirmations = toml_int_in(server, "btc_confirmations");
  if (confirmations.ok)
  {
    config.btc_confirmations = (uint8_t)confirmations.u.i;
  }

  // Optional: flush_freq, with default
  toml_datum_t flush_freq = toml_int_in(server, "backup_freq");
  if (flush_freq.ok)
  {
    config.flush_freq = (int)flush_freq.u.i;
  }

  // Optional: integrity_freq, with default
  toml_datum_t integrity_freq = toml_int_in(server, "integrity_freq");
  if (integrity_freq.ok)
  {
    config.integrity_freq = (int)integrity_freq.u.i;
  }

  // ** NEW: Optional: synchronization_enabled, with default **
  toml_datum_t sync_enabled = toml_bool_in(server, "synchronization_enabled");
  if (sync_enabled.ok)
  {
    config.synchronization_enabled = sync_enabled.u.b;
  }

  // Optional: udp_payload_threshold, with default
  toml_datum_t udp_thr = toml_int_in(server, "udp_effective_payload");
  if (udp_thr.ok)
  {
    config.udp_payload_threshold = (int)udp_thr.u.i;
  }

  config.raida_no = (int)raida_no.u.i;
  config.port = (int)port.u.i;
  config.coin_id = (uint8_t)coin_id.u.i;

  // Mandatory: raida_servers array
  toml_array_t *raida_servers_array = toml_array_in(server, "raida_servers");
  if (!raida_servers_array)
  {
    error("Mandatory key 'raida_servers' not found in config file");
    toml_free(conf);
    return -1;
  }

  for (i = 0; i < TOTAL_RAIDA_SERVERS; i++)
  {
    toml_datum_t host_port = toml_string_at(raida_servers_array, i);
    if (!host_port.ok)
    {
      error("Failed to parse raida_servers array. Item #%d", i);
      toml_free(conf);
      return -1;
    }

    char *hp_copy = strdup(host_port.u.s);
    free(host_port.u.s); // free memory from toml_string_at

    tp = strtok(hp_copy, ":");
    if (tp == NULL)
    {
      error("Failed to parse host from raida_servers item #%d", i);
      free(hp_copy);
      toml_free(conf);
      return -1;
    }
    char *host_str = strdup(tp);

    tp = strtok(NULL, ":");
    if (tp == NULL)
    {
      error("Failed to parse port from raida_servers item #%d", i);
      free(host_str);
      free(hp_copy);
      toml_free(conf);
      return -1;
    }
    char *port_str = strdup(tp);

    // Resolve address
    res = NULL;
    rv = getaddrinfo(host_str, port_str, &hints, &res);
    if (rv != 0)
    {
      error("Failed to resolve RAIDA%d: %s:%s -> %s", i, host_str, port_str, gai_strerror(rv));
      free(host_str);
      free(port_str);
      free(hp_copy);
      toml_free(conf);
      return -1;
    }

    found = 0;
    for (ptr = res; ptr != NULL; ptr = ptr->ai_next)
    {
      if (ptr->ai_family == AF_INET)
      {
        config.raida_addrs[i] = malloc(sizeof(struct sockaddr_in));
        memcpy(config.raida_addrs[i], ptr->ai_addr, sizeof(struct sockaddr_in));
        config.raida_servers[i] = strdup(host_str);
        config.raida_servers_ports[i] = atoi(port_str);
        found = 1;
        break;
      }
    }
    freeaddrinfo(res);
    free(host_str);
    free(port_str);
    free(hp_copy);

    if (!found)
    {
      error("Failed to find an IPv4 address for RAIDA%d", i);
      toml_free(conf);
      return -1;
    }
    debug("Neigbour RAIDA%d %s:%d", i, config.raida_servers[i], config.raida_servers_ports[i]);
  }

  dump_config();
  debug("Configuration parsed successfully");

  toml_free(conf);
  return 0;
}

/*
 * Prints the configuration to stdout
 */
void dump_config(void)
{
  debug("Configuration:");
  debug("- RAIDA #%d", config.raida_no);
  debug("- Port %d", config.port);
  debug("- Workdir %s", config.cwd);
  debug("- Flush Frequency %ds", config.flush_freq);
  debug("- Integrity Checking Frequency %ds", config.integrity_freq);
  debug("- Synchronization Enabled: %s", config.synchronization_enabled ? "Yes" : "No");
  debug("- UDP Payload threshold %d bytes", config.udp_payload_threshold);
}
