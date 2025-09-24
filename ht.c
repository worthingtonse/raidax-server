#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>


#include "commands.h"
#include "ht.h"
#include "db.h"
#include "config.h"
#include "log.h"


struct ht ipht[HT_SIZE];


int init_ht(void) {
  int i;
  debug("Initializing IP hash table");

  memset(ipht, 0, sizeof(struct ht) * HT_SIZE);

  return 0;
}


int check_add_ipht(char *ip) {
  struct ht *hte;
  struct in_addr inp;
  uint32_t ipb;
  uint16_t key;
  int rv;
  time_t now;

  debug("Checking ip %s", ip);

  if (!memcmp(ip, "127.0", 5))
    return 0;

  inet_aton(ip, &inp);

  ipb = inp.s_addr;
  key = (ipb >> 16) & 0xffff;

  debug("ip %x, key %x", ipb, key);

  if (key >= HT_SIZE) {
    error("Invalid key size %d. Max is %d", key, HT_SIZE);
    return -1;
  }
     
  time(&now);
  hte = &ipht[key];

  debug("IP rate count %d. Seen %llu", hte->count, hte->seen);

  if (hte->seen + HT_PERIOD < now) {
    debug("Record expired. Good");

    hte->seen = now;
    hte->count = 1;
    return 0;
  }

  if (hte->count > HT_MAX_PER_PERIOD) {
    error("Request rate denied");
    return -1;
  }

  hte->seen = now;
  hte->count++;

  debug("rate is ok");

  return 0;

}

