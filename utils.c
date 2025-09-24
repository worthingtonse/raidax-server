/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : utils.c
#   Last Modified : 2025-07-17 12:58
#   Describe      : Various utils for RAIDAX, updated for dual hash support.
#                 ** FIXED: generate_an_hash now returns full 32-byte key for 256-bit AES **
#
# ====================================================*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <fcntl.h>       // For O_RDONLY
#include <unistd.h>      // For read() and close()
#include <errno.h>       // For errno
#include <openssl/sha.h> // For SHA256
#include <openssl/hmac.h>

#include "db.h"
#include "utils.h"
#include "log.h"
#include "md5.h" // Include for legacy MD5 support

unsigned int crc32b(unsigned char *message, int len)
{
  int i, j;
  unsigned int byte, crc, mask;

  i = 0;
  crc = 0xFFFFFFFF;
  while (i < len)
  {
    byte = message[i];
    crc = crc ^ byte;
    for (j = 7; j >= 0; j--)
    {
      mask = -(crc & 1);
      crc = (crc >> 1) ^ (0xEDB88320 & mask);
    }
    i = i + 1;
  }
  return ~crc;
}

uint32_t get_sn(unsigned char *buf)
{
  return get_u32(buf);
}

uint32_t get_u32(unsigned char *buf)
{
  return (uint32_t)buf[0] << 24 |
         (uint32_t)buf[1] << 16 |
         (uint32_t)buf[2] << 8 |
         (uint32_t)buf[3];
}

void put_sn(uint32_t val, unsigned char *buf)
{
  put_u32(val, buf);
}

void put_u32(uint32_t val, unsigned char *buf)
{
  buf[0] = (val >> 24) & 0xff;
  buf[1] = (val >> 16) & 0xff;
  buf[2] = (val >> 8) & 0xff;
  buf[3] = val & 0xff;
}

uint8_t get_mfs(void)
{
  time_t now;
  struct tm *t;
  uint8_t res;

  time(&now);
  t = gmtime(&now);
  // Epoch February, 2023
  // Year is returned like y - 1900
  // Month is returned from 0 to 11
  int y = t->tm_year - 123;
  int m = t->tm_mon - 1;
  res = y * 12 + m;
  return res;
}

void hex2bin(char *input, char *res, int len)
{
  char *pos = input;
  for (size_t count = 0; count < len; count++)
  {
    sscanf(pos, "%2hhx", &res[count]);
    pos += 2;
  }
}

uint64_t get_den_value(int8_t den)
{
  int8_t dz;
  double v;
  dz = den + 8;
  v = pow(10, dz);
  return (uint64_t)v;
}

uint64_t swap_uint64(uint64_t val)
{
  return ((((long long)htonl(val)) << 32) + (htonl((val) >> 32)));
}

uint64_t coin_value(int8_t den, uint32_t sn)
{
  uint64_t value = 0;
  switch (den)
  {
  case DEN_0_00000001:
    value = 1;
    break;
  case DEN_0_0000001:
    value = 10;
    break;
  case DEN_0_000001:
    value = 100;
    break;
  case DEN_0_00001:
    value = 1000;
    break;
  case DEN_0_0001:
    value = 10000;
    break;
  case DEN_0_001:
    value = 100000;
    break;
  case DEN_0_01:
    value = 1000000;
    break;
  case DEN_0_1:
    value = 10000000;
    break;
  case DEN_1:
    value = 100000000;
    break;
  case DEN_10:
    value = 1000000000;
    break;
  case DEN_100:
    value = 10000000000ULL;
    break;
  case DEN_1000:
    value = 100000000000ULL;
    break;
  case DEN_10000:
    value = 1000000000000ULL;
    break;
  case DEN_100000:
    value = 10000000000000ULL;
    break;
  case DEN_1000000:
    value = 100000000000000ULL;
    break;
  }
  return value;
}

int generate_random_bytes(unsigned char *buf, int len)
{
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
  {
    error("Failed to open /dev/urandom: %s", strerror(errno));
    return -1;
  }
  ssize_t bytes_read = 0;
  while (bytes_read < len)
  {
    ssize_t result = read(fd, buf + bytes_read, len - bytes_read);
    if (result < 0)
    {
      error("Failed to read from /dev/urandom: %s", strerror(errno));
      close(fd);
      return -1;
    }
    bytes_read += result;
  }
  close(fd);
  if (bytes_read != len)
  {
    error("Failed to read enough bytes from /dev/urandom. Got %zd, expected %d", bytes_read, len);
    return -1;
  }
  return 0;
}

/*
 * ** Legacy AN Generation Function (MD5) **
 * Generates a 16-byte Authenticity Number (AN) by hashing the input data using the original MD5 algorithm.
 * This is used for backward compatibility with older clients and for file-based ANs.
 *
 * @param input The data to be hashed.
 * @param input_len The length of the input data.
 * @param output_an A 16-byte buffer to store the resulting AN.
 */
void generate_an_hash_legacy(const unsigned char *input, int input_len, unsigned char *output_an)
{
  md5ilen((char *)input, (char *)output_an, input_len);
}

/*
 * ** FIXED: Secure Key Generation Function (SHA-256) **
 * Generates a 32-byte encryption key by hashing the input data using SHA-256.
 * Returns the full 32-byte SHA-256 hash for use with 256-bit AES encryption.
 *
 * @param input The data to be hashed.
 * @param input_len The length of the input data.
 * @param output_key A 32-byte buffer to store the resulting encryption key.
 */
void generate_an_hash(const unsigned char *input, int input_len, unsigned char *output_key)
{
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, input, input_len);

  // FIXED: Return full 32-byte SHA-256 hash for 256-bit AES
  SHA256_Final(output_key, &sha256);
}

/*
 * ** NEW: HMAC Computation Function (SHA-256) **
 * Generates a 32-byte HMAC-SHA256 tag for a given data buffer using a secret key.
 *
 * @param data The data to be authenticated.
 * @param data_len The length of the data.
 * @param key The 32-byte secret key (typically encryption_an_256 for encryption type 4 5 and so on).
 * @param output_hmac A 32-byte buffer to store the resulting HMAC tag.
 */
void compute_hmac(const unsigned char *data, int data_len, const unsigned char *key, unsigned char *output_hmac)
{
  unsigned int len = 32;
  HMAC(EVP_sha256(), key, 32, data, data_len, output_hmac, &len);
}