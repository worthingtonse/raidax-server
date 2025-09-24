/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium 
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : log.c
#   Last Modified : 2023-02-20 10:43
#   Describe      : This file contains log helper functions
#
# ====================================================*/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>

#include "log.h"


// Main mutex to serialize access to log records
pthread_mutex_t log_mtx;


/*
 * This function globally initializes log subsystem
 * returns 0 un success, returns a negative value on failure
 */
int init_logs() {
  if (pthread_mutex_init(&log_mtx, NULL) < 0)
    return -1;

  setvbuf(stdout, NULL, _IONBF, 0);

  return 0;
}

/*
 *
 * We are writing directly to the STDOUT
 * This is processes by the SystemD and can be viewed
 * by journalctl command
 *
 * It is easy to extend this function and have it write
 * log entries anywhere, e.g. to a file
 * 
 */
void do_log(const char *prefix, const char *fmt, va_list args) {
  char buf[MAX_LOG_RECORD];

  int length = strlen(fmt);
  if (length > MAX_LOG_RECORD - 2) {
    length = MAX_LOG_RECORD - 2;
  }

  memcpy(buf, fmt, length);
  buf[length] = '\n';
  buf[length + 1] = 0;

  pthread_mutex_lock(&log_mtx);
  printf("%x: [%s] ", (unsigned int) pthread_self(), prefix);

  vprintf(buf, args);
  pthread_mutex_unlock(&log_mtx);
}


/*
 * Writes a debug line 
 */
void debug(const char *fmt, ...) {
  va_list args;

  if (!DEBUG) 
    return;

  va_start(args, fmt);
  do_log("DEBUG", fmt, args);
  va_end(args);
}

/*
 * Writes a warning
 */
void warning(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  do_log("WARN", fmt, args);
  va_end(args);
}



/*
 * Writes a error in the log file line 
 */
void error(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  do_log("ERROR", fmt, args);
  va_end(args);
}

