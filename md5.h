/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium 
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : md5.h
#   Last Modified : 2023-02-14 10:49
#   Describe      : MD5 function header
#
# ====================================================*/

#ifndef LIBRARY_H
#define LIBRARY_H

void md5(char *, char *);
void md5ilen(char *, char *, int);

typedef struct{
	uint64_t size;        // Size of input in bytes
	uint32_t buffer[4];   // Current accumulation of hash
	uint8_t input[64];    // Input to be used in the next step
	uint8_t digest[16];   // Result of algorithm
} MD5Context;

void md5Init(MD5Context *ctx);
void md5Update(MD5Context *ctx, uint8_t *input, size_t input_len);
void md5Finalize(MD5Context *ctx);
void md5Step(uint32_t *buffer, uint32_t *input);

uint32_t F(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t G(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t H(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t I(uint32_t X, uint32_t Y, uint32_t Z);

uint32_t rotateLeft(uint32_t x, uint32_t n);

#endif	
