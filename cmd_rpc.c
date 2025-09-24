/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_rpc.c
#   Last Modified : 2024-07-26 15:38
#   Describe      : Auth Commands
#
# ====================================================*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "db.h"
#include "config.h"
#include "utils.h"
#include "crossover.h"

extern struct config_s config;

#define RRTYPE_A 0x1
#define RRTYPE_SRV 0x2

/*
 * Resolves a DNS name
 */
void cmd_nslookup(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  uint8_t rrtype;
  char *fqdn, *p, *sp, *ssp;
  char zone_path[PATH_MAX];
  FILE *fp;
  char *line, *saved_line = NULL;
  size_t len;
  ssize_t read;
  int found, i;
  uint32_t addr;
  uint16_t port;

  debug("CMD Nslookup");

  // 16CH+1RR+3FQDN (at least) + 2EOF
  if (ci->body_size < 22)
  {
    error("Invalid command length: %d. Expected at least 22", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  rrtype = (uint8_t)payload[0];
  fqdn = &payload[1];
  fqdn[ci->body_size - 16 - 1 - 2] = 0;

  sp = ssp = NULL;

  // Validate
  p = fqdn;
  while (*p != 0)
  {
    if (isalpha(*p) || isdigit(*p) || *p == '-' || *p == '.')
    {
      p++;
      continue;
    }

    error("Invalid domain %s (%c %x)", fqdn, *p, *p);
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  if (rrtype != RRTYPE_SRV && rrtype != RRTYPE_A)
  {
    error("Invalid rrtype %d", rrtype);
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  debug("Address type %d v %s", rrtype, fqdn);
  sprintf((char *)&zone_path, "%s/Zones/%s.zone", config.cwd, fqdn);

  fp = fopen(zone_path, "r");
  if (fp == NULL)
  {
    error("Failed to open %s: %s", zone_path, strerror(errno));
    ci->command_status = ERROR_NXDOMAIN;
    return;
  }

  found = 0;
  i = 0;
  while ((read = getline(&saved_line, &len, fp)) != -1)
  {
    line = saved_line;
    debug("po %p", line);
    if (line[read - 1] == 0xa)
    {
      line[read - 1] = 0;
    }

    debug("r %s", line);
    while (*line == ' ')
    {
      line++;
      continue;
    }

    if (*line == '#')
      continue;

    if (read < 10)
    {
      continue;
    }

    sp = strtok(line, " ");
    if (sp == NULL)
    {
      debug("WARN: malformed string %s", line);
      continue;
    }

    if (rrtype == RRTYPE_SRV)
    {
      if (strncmp(sp, "SRV", 3))
        continue;

      sp = strtok(NULL, " ");
      if (sp == NULL)
      {
        debug("WARN: malformed string %s", line);
        continue;
      }

      ssp = strtok(sp, ":");
      if (ssp == NULL)
      {
        debug("WARN: malformed string %s", sp);
        continue;
      }

      if (inet_aton(ssp, (struct in_addr *)&addr) < 0)
      {
        error("Failed to parse addr %s", ssp);
        continue;
      }

      ssp = strtok(NULL, ":");
      if (ssp == NULL)
      {
        debug("WARN: malformed string %s", ssp);
        continue;
      }

      port = ntohs(atoi(ssp));
    }
    else if (rrtype == RRTYPE_A)
    {
      if (strncmp(sp, "A", 1))
        continue;

      sp = strtok(NULL, " ");
      if (sp == NULL)
      {
        debug("WARN: malformed string %s", line);
        continue;
      }

      debug("sp %s", sp);

      if (inet_aton(sp, (struct in_addr *)&addr) < 0)
      {
        error("Failed to parse addr %s", sp);
        continue;
      }
    }

    found = 1;
    break;
  }

  if (saved_line != NULL)
    free(saved_line);

  fclose(fp);

  if (!found)
  {
    error("Failed to find record");
    ci->command_status = ERROR_NXRECORD;
    return;
  }

  ci->output_size = 6;
  ci->output = (char *)malloc(sizeof(char) * ci->output_size);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  memset(ci->output, 0, ci->output_size);
  memcpy(ci->output, (unsigned char *)&addr, 4);
  memcpy(ci->output + 4, (unsigned char *)&port, 2);

  ci->command_status = (char)STATUS_SUCCESS;

  debug("CMD nslookup finished");
}
