#ifndef _HT
#define _HT

#include <time.h>
#include <sys/types.h>

#define HT_SIZE 65536
#define HT_PERIOD 28800
#define HT_MAX_PER_PERIOD 30

struct ht {
  uint16_t count;
  time_t seen;
};

int init_ht(void);

int check_add_ipht(char *);

#endif




