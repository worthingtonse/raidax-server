/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : utils.h
#   Last Modified : 2025-07-17 13:01
#   Describe      : Utils header, updated for dual hash support.
#                 ** FIXED: Updated generate_an_hash documentation for 32-byte output **
#
# ====================================================*/

#ifndef _UTILS_H
#define _UTILS_H

#include <stdint.h> // Required for uint types
#include <openssl/hmac.h>

// Calculates CRC32b checksum for a given buffer.
unsigned int crc32b(unsigned char *, int);

// Functions for handling 32-bit unsigned integers in big-endian format.
uint32_t get_sn(unsigned char *);
uint32_t get_u32(unsigned char *);
void put_sn(uint32_t, unsigned char *);
void put_u32(uint32_t, unsigned char *);

// Gets the "Months From Start" value based on the current system time.
uint8_t get_mfs(void);

// Calculates the value of a coin based on its denomination.
uint64_t get_den_value(int8_t);

// Converts a hexadecimal string to a binary buffer.
void hex2bin(char *, char *, int);

// Swaps the byte order of a 64-bit unsigned integer (for endianness conversion).
uint64_t swap_uint64(uint64_t);

// Calculates the value of a coin.
uint64_t coin_value(int8_t den, uint32_t sn);

// Generates a specified number of cryptographically secure random bytes.
int generate_random_bytes(unsigned char *buf, int len);

// ** FIXED: Secure 256-bit Key Generation using SHA-256 **
// Generates a 32-byte encryption key by hashing the input data using SHA-256.
// Returns the full 32-byte hash for use with 256-bit AES encryption.
void generate_an_hash(const unsigned char *input, int input_len, unsigned char *output_key);

// ** Legacy AN Generation using MD5 **
// Generates a 16-byte Authenticity Number (AN) using the original MD5 hash.
// This is for backward compatibility with older clients
void generate_an_hash_legacy(const unsigned char *input, int input_len, unsigned char *output_an);

// Computes an HMAC-SHA256 tag for the given data and key.
void compute_hmac(const unsigned char *data, int data_len, const unsigned char *key, unsigned char *output_hmac);

#endif // _UTILS_H