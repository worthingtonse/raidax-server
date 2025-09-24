/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : main.c
#   Last Modified : 2025-07-24 11:05
#   Describe      : Main Entry File for the RAIDAX Server, fully optimized.
#
# ====================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <sys/sysinfo.h>

#include "main.h"
#include "config.h"
#include "net.h"
#include "log.h"
#include "thpool.h"
#include "db.h"
#include "locker.h"
#include "crossover.h"
#include "integrity.h"
#include "stats.h"
#include "iaesni.h"
#include "ht.h"

// Global variable that keeps the listeners running
int is_finished;

// Needs to start syncing process (legacy, may be deprecated)
int need_sync;

// Whether the CPU supports Intel AES
int aes_hw;

// From log.c
extern pthread_mutex_t log_mtx;

// Main thread pool
threadpool thpool;

// config
extern struct config_s config;

void cleanup_db_threads(void);
void cleanup_integrity_threads(void);

/*
 * Signal Hanlder.
 * This is called when the program is terminated or is sent a signal
 * CTRL-C for example
 */
void handle_signal(int signal, siginfo_t *info, void *ctx)
{
  // just in case we interrupted inside log file
  pthread_mutex_unlock(&log_mtx);

  debug("Signalled: %d", signal);

  if (signal == SIGUSR1)
  {
    debug("Need sync pages");
    need_sync = 1;
    return;
  }

  debug("Terminating...");
  cleanup_all_threads();
  exit(0);
}

/*
 * Installs signal handlers
 */
int install_signal_handlers()
{
  struct sigaction sa;

  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = handle_signal;

  if (sigaction(SIGTERM, &sa, NULL) == -1)
  {
    error("Failed to setup SIGTERM handler");
    return -1;
  }
  if (sigaction(SIGINT, &sa, NULL) == -1)
  {
    error("Failed to setup SIGINT handler");
    return -1;
  }
  if (sigaction(SIGHUP, &sa, NULL) == -1)
  {
    error("Failed to setup SIGHUP handler");
    return -1;
  }
  if (sigaction(SIGPIPE, &sa, NULL) == -1)
  {
    error("Failed to setup SIGPIPE handler");
    return -1;
  }
  if (sigaction(SIGUSR1, &sa, NULL) == -1)
  {
    error("Failed to setup SIGUSR1 handler");
    return -1;
  }

  debug("Signal handlers set");
  return 0;
}

void cleanup_all_threads(void)
{
  debug("Shutting down all background threads...");
  is_finished = 1;
  cleanup_db_threads();
  cleanup_integrity_threads();
  thpool_destroy(thpool);
  debug("All background threads shut down cleanly.");
}

/*
 * Main entry point
 */
int main(int argc, char *argv[])
{
  int cores, thpool_size;

  // First off, init logs
  if (init_logs() < 0)
  {
    fprintf(stderr, "Failed to init log subsystem\n");
    exit(1);
  }

  debug("Starting RAIDA Server. Build Time %s", __BUILD_TIME);

  if (read_config(argv[0]) < 0)
  {
    fprintf(stderr, "Failed to read config file\n");
    exit(1);
  }

  if (install_signal_handlers() < 0)
  {
    fprintf(stderr, "Failed to install signal handlers\n");
    exit(1);
  }

  aes_hw = check_for_aes_instructions();
  debug("HW AES support: %s", aes_hw ? "Yes" : "No");

  // ** OPTIMIZATION: init_db now initializes the on-demand cache system **
  // It also starts its own background persistence thread.
  if (init_db() < 0)
  {
    fprintf(stderr, "Failed to init database\n");
    exit(1);
  }
  if (init_udp_ci_pool() < 0)
  {
    fprintf(stderr, "Failed to init UDP CI Pool\n");
    exit(1);
  }
  // Init other modules
  if (init_ticket_storage() < 0)
  {
    fprintf(stderr, "Failed to init ticket memory pool\n");
    exit(1);
  }
  if (init_locker_index() < 0)
  {
    fprintf(stderr, "Failed to init locker indexes\n");
    exit(1);
  }
  if (init_crossover_index() < 0)
  {
    fprintf(stderr, "Failed to init crossover indexes\n");
    exit(1);
  }
  if (init_stats() < 0)
  {
    fprintf(stderr, "Failed to init stats\n");
    exit(1);
  }
  if (init_ht() < 0)
  {
    fprintf(stderr, "Failed to init IP hash table");
    exit(1);
  }

  // ** NEW: Initialize the new Merkle Tree integrity system **
  // This function starts its own background thread.
  if (init_integrity_system() < 0)
  {
    fprintf(stderr, "Failed to start integrity system\n");
    exit(1);
  }

  // Configure and initialize the thread pool
  if (config.threads > 0)
  {
    thpool_size = (int)config.threads;
  }
  else
  {
    thpool_size = THPOOL_SIZE;
    cores = get_nprocs();
    if (cores > THPOOL_SIZE)
    {
      thpool_size = cores;
    }
  }
  debug("Setting thread pool size to %d", thpool_size);
  thpool = thpool_init(thpool_size);
  if (thpool == NULL)
  {
    fprintf(stderr, "Failed to init thread pool\n");
    exit(1);
  }

  is_finished = 0;
  need_sync = 0;

  // This function blocks while listening for network requests
  if (init_and_listen_sockets() < 0)
  {
    fprintf(stderr, "Failed to listen network sockets\n");
    exit(1);
  }
  cleanup_all_threads();
  debug("Program finished");
  return 0;
}