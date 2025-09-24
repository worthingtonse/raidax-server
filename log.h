/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium 
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : log.h
#   Last Modified : 2023-01-09 17:34
#   Describe      : 
#
# ====================================================*/

#ifndef  _LOG_H
#define  _LOG_H


// This variable controls whether the additional
// log entries will be recorded
#define DEBUG 1

// Limit the maximum line size
#define MAX_LOG_RECORD 1024


int init_logs(void);

void debug(const char *, ...);
void warning(const char *, ...);
void error(const char *, ...);
void do_log(const char *, const char *, va_list);

#endif // _LOG_H


