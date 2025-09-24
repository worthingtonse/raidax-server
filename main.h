/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : main.h
#   Last Modified : 2024-12-29 09:31
#   Describe      : Header for the main file
#
# ====================================================*/

#ifndef _MAIN_H
#define _MAIN_H

// If not defined in the config file
#define DEFAULT_FLUSH_FREQ 10
#define DEFAULT_INTEGRITY_FREQ 14400
#define DEFAULT_UDP_PAYLOAD_THRESHOLD 1440

#define VERSION "20250323"

int install_signal_handlers(void);
void cleanup_all_threads(void);

// Four threads in the pool
#define THPOOL_SIZE 8

#ifndef __BUILD_TIME
#define __BUILD_TIME "unset"
#endif

#endif // _MAIN_H
