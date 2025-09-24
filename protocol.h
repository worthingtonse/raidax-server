/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : protocol.h
#   Last Modified : 2025-07-29 12:45
#   Describe      : RAIDX main protocol header.
#
#
# ====================================================*/

#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <inttypes.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <pthread.h> // Required for pthread_mutex_t

// UPDATED: Variable header size constants
#define REQUEST_HEADER_SIZE_LEGACY 32  // Type 0, 1, 2 (legacy)
#define REQUEST_HEADER_SIZE_MODERN 48  // Type 4, 5 (modern)
#define RESPONSE_HEADER_SIZE_LEGACY 32 // Type 0, 1, 2 (legacy)
#define RESPONSE_HEADER_SIZE_MODERN 48 // Type 4, 5 (modern)

// BACKWARD COMPATIBILITY: Keep original constants pointing to maximum size
// This ensures existing code that uses these constants continues to work
#define REQUEST_HEADER_SIZE REQUEST_HEADER_SIZE_MODERN   // 48 bytes (safe for all types)
#define RESPONSE_HEADER_SIZE RESPONSE_HEADER_SIZE_MODERN // 48 bytes (safe for all types)

// UPDATED: Variable nonce size constants
#define NONCE_SIZE_LEGACY 16 // Type 0, 1, 2
#define NONCE_SIZE_MODERN 24 // Type 4, 5

// BACKWARD COMPATIBILITY: Keep original constant pointing to maximum size
#define NONCE_SIZE NONCE_SIZE_MODERN // 24 bytes (safe for all types)

// The number of RAIDA servers
#define TOTAL_RAIDA_SERVERS 25

// Basic coin struct
typedef struct
{
  int8_t denomination;
  uint32_t sn;
} coin_t;

// Enum for tracking the state of a non-blocking connection
typedef enum
{
  STATE_WANT_READ_HEADER, // Waiting to read the request header
  STATE_WANT_READ_BODY,   // Waiting to read the request body
  STATE_PROCESSING,       // Request is being processed by a worker thread
  STATE_WANT_WRITE,       // Ready to write the response
  STATE_DONE              // Connection finished, ready to be closed
} connection_state_t;

// UPDATED: Represents client connection with support for variable header sizes and two coins
typedef struct
{
  // If UDP it holds client address
  struct sockaddr *sa;

  // Client socket
  int sk;

  // Echo Bytes from the original 32-byte header (bytes 6 and 7)
  uint8_t e0, e1;

  // Incoming Request
  int body_size;
  unsigned char *body;

  // UPDATED: Encryption Data with support for two coins (Type 5)
  int8_t encryption_denomination;  // First coin denomination
  uint32_t encryption_sn;          // First coin SN
  int8_t encryption_denomination2; // Second coin denomination (Type 5 only)
  uint32_t encryption_sn2;         // Second coin SN (Type 5 only)
  int encryption_type;
  unsigned char encryption_an[16];
  unsigned char encryption_an_256[32]; //  32 bytes for Type 4/5

  unsigned char nonce[16];

  // UPDATED: Nonce fields, sized for the maximum 24-byte nonce but supporting legacy 12-byte
  unsigned char request_nonce[NONCE_SIZE];  // 24 bytes max
  unsigned char response_nonce[NONCE_SIZE]; // 24 bytes max

  // Data returned by client.
  int output_size;
  unsigned char *output;
  unsigned char command_status;

  // For the legacy challenge-response mechanism (Type 0, 1, 2)
  unsigned char challenge_hash[16];

  // Starting time
  struct timeval start_time;

  // Processed command
  uint8_t cgroup;
  uint8_t command;

  uint8_t shard_id;

  // IP address
  char ip[16];
  unsigned long exec_time;

  uint8_t coin_id;

  // Fields for non-blocking I-O state management
  connection_state_t state;
  unsigned char read_buf[REQUEST_HEADER_SIZE]; // Uses maximum size for safety
  int bytes_to_read;
  int bytes_read;

  unsigned char *write_buf;
  int bytes_to_write;
  int bytes_written;

  int is_udp_pooled;

} conn_info_t;

// Encryption type definitions
#define ENCRYPTION_TYPE_NONE 0
#define ENCRYPTION_TYPE_AES 1    // Single coin, 16-byte AN directly, 32-byte header
#define ENCRYPTION_TYPE_LOCKER 2 // Locker coin, 16-byte key, 32-byte header
// Type 3 is reserved/unused
#define ENCRYPTION_TYPE_AES_256_SINGLE_KEY 4 // Single coin, SHA-256 hash, 48-byte header
#define ENCRYPTION_TYPE_AES_256_DOUBLE_KEY 5 // Two coins, concatenate + SHA-256, 48-byte header

enum STATUS_CODE
{
  NO_ERROR = 0,

  ERROR_INVALID_CLOUD_ID = 1,
  ERROR_INVALID_SPLIT_ID = 2,
  ERROR_INVALID_RAIDA_ID = 3,
  ERROR_INVALID_SHARD_ID = 4,
  ERROR_INVALID_COMMAND_GROUP = 5,
  ERROR_INVALID_COMMAND = 6,
  ERROR_INVALID_COIN_ID = 7,
  ERROR_INVALID_UDP_FRAME_COUNT = 15,
  ERROR_INVALID_PACKET_LENGTH = 16,
  ERROR_UDP_FRAME_TIMEOUT = 17,
  ERROR_WRONG_RAIDA = 18,
  ERROR_SHARD_NOT_AVAILABLE = 20,
  ERROR_ENCRYPTION_COIN_NOT_FOUND = 25,
  ERROR_INVALID_ENCRYPTION_CODE = 27,
  ERROR_INVALID_EOF = 33,
  ERROR_INVALID_ENCRYPTION = 34,
  ERROR_EMPTY_REQUEST = 36,
  ERROR_INVALID_CRC = 37,
  ERROR_ADMIN_AUTH = 38,

  ERROR_COINS_NOT_DIV = 39,
  ERROR_INVALID_SN_OR_DENOMINATION = 40,
  ERROR_PAGE_IS_NOT_RESERVED = 41,

  ERROR_NO_TICKET_SLOT = 42,
  ERROR_NO_TICKET_FOUND = 43,
  ERROR_TICKET_CLAIMED_ALREADY = 44,

  ERROR_TOO_MANY_COINS = 45,
  ERROR_INVALID_SHARD = 46,
  ERROR_DELETE_COINS = 47,

  ERROR_LEGACY_DB = 48,

  ERROR_CROSSOVER_FULL = 49,
  ERROR_INVALID_TRADE_COIN = 50,
  ERROR_TRADE_LOCKER_NOT_FOUND = 51,
  ERROR_NO_PRIVATE_KEY = 52,

  ERROR_NOT_IMPLEMENTED = 89,
  ERROR_BAD_COINS = 90,

  ERROR_TRADE_LOCKER_EXISTS = 148,
  ERROR_NO_TRADE_LOCKER = 149,
  STATUS_WAITING = 150,

  ERROR_NO_BTC_IN_WALLET = 152,
  ERROR_FEW_COINS_IN_LOCKER = 153,
  ERROR_LOCKER_USED = 154,
  ERROR_REQUEST_RATE = 160,

  ERROR_TXN_PROCESSED = 177,
  ERROR_CRYPTO_CONNECT = 178,
  ERROR_LOCKER_EMPTY_OR_NOT_EXISTS = 179,
  ERROR_PROXY_CONNECT = 180,
  ERROR_PRICE = 181,
  ERROR_NO_COINS = 182,

  STATUS_TX_SEEN = 183,
  ERROR_NXRECORD = 184,
  ERROR_NXDOMAIN = 185,
  ERROR_UNKNOWN = 186,
  ERROR_PROXY = 187,

  ERROR_KEY_BUILD = 188,
  ERROR_EXTERNAL_BACKEND = 189,

  ERROR_TX_EMPTY = 190,
  ERROR_TX_NOT_EXIST = 191,
  ERROR_AMOUNT_MISMATCH = 192,
  ERROR_NO_ENTRY = 193,

  ERROR_FILESYSTEM = 194,
  ERROR_INVALID_KEY_START = 195,
  ERROR_INVALID_KEY_LENGTH = 196,

  ERROR_COIN_LOAD = 197,
  ERROR_INVALID_PARAMETER = 198,

  ERROR_INVALID_PAN = 199,

  ERROR_FILE_EXISTS = 201,
  ERROR_FILE_NOT_EXIST = 202,

  ERROR_INVALID_TRANSACTION = 203,

  // HMAC specific error code
  ERROR_INVALID_HMAC = 204,

  ERROR_BLOCKCHAIN = 204,
  ERROR_ASSEMBLE = 205,

  // For Find service
  STATUS_FIND_NEITHER = 208,
  STATUS_FIND_ALL_AN = 209,
  STATUS_FIND_ALL_PAN = 210,
  STATUS_FIND_MIXED = 211,

  // NEW: RKE-specific error codes
  // ERROR_SECRET_NOT_FOUND = 212,

  STATUS_ALL_PASS = 241,
  STATUS_ALL_FAIL = 242,
  STATUS_MIXED = 243,

  STATUS_SUCCESS = 250,

  ERROR_INTERNAL = 252,
  ERROR_NETWORK = 253,
  ERROR_MEMORY_ALLOC = 254,
  ERROR_INVALID_ROUTING = 255,

};

enum COMMAND_GROUP
{
  NO_COMMAND_GROUP = 0,
  AUTH = 1,
  HEALING = 2,
  ADMIN = 3,
  KEY_EXCHANGE = 4,
  BANKING = 5,
  CHAT = 6,
  BLOCKCHAIN = 7,
  LOCKER = 8,
  CHANGE = 9,
  SHARD = 10,
  CROSSOVER = 11,
  RPC = 12,
  FILESYSTEM = 13,
  INTEGRITY = 14,
  RKE = 15, // Added RKE command group
};

enum COIN_SHARD
{
  SHARD_UNKNOWN = 0,
  SHARD_CLOUDCOIN = 1,
  SHARD_SUPERCOIN = 2,
  SHARD_NEW = 3,
};

#define MAX_SHARD SHARD_NEW

// UPDATED: Maximum command group to include RKE
#define MAX_COMMAND_GROUP RKE
#define MAX_COMMAND 255

//  Helper function to get appropriate header size for encryption type
static inline int get_header_size_for_encryption_type(int encryption_type)
{
  // Legacy types (0, 1, 2) use 32-byte headers
  // Modern types (4, 5) use 48-byte headers
  if (encryption_type == ENCRYPTION_TYPE_NONE ||
      encryption_type == ENCRYPTION_TYPE_AES ||
      encryption_type == ENCRYPTION_TYPE_LOCKER)
  {
    return REQUEST_HEADER_SIZE_LEGACY; // 32 bytes
  }
  else
  {
    return REQUEST_HEADER_SIZE_MODERN; // 48 bytes
  }
}

//  Helper function to get appropriate nonce size for encryption type
static inline int get_nonce_size_for_encryption_type(int encryption_type)
{
  // Legacy types (0, 1, 2) use 12-byte nonces
  // Modern types (4, 5) use 24-byte nonces
  if (encryption_type == ENCRYPTION_TYPE_NONE ||
      encryption_type == ENCRYPTION_TYPE_AES ||
      encryption_type == ENCRYPTION_TYPE_LOCKER)
  {
    return NONCE_SIZE_LEGACY;
  }
  else
  {
    return NONCE_SIZE_MODERN; // 24 bytes
  }
}

// Protocol validation and processing functions
int validate_header(unsigned char *, conn_info_t *);
int validate_decrypt_body(conn_info_t *);
void send_command_error(int, conn_info_t *);
void get_response_header(char *, int, int, conn_info_t *);
int get_header_size_for_encryption_type(int encryption_type);
int get_response_header_size_for_encryption_type(int encryption_type);

// Command handler type
typedef void(command_handler_t)(conn_info_t *);

void run_command(void *);
void prepare_response(conn_info_t *);
void finish_command(conn_info_t *);

unsigned char *get_body_payload(conn_info_t *);

// Ticket system constants and structures
#define TOTAL_RAIDA_SERVERS 25
#define TICKET_POOL_SIZE 512
#define MAX_COINS_PER_TICKET 4096
#define TICKET_RELEASE_SECONDS 300

struct ticket_entry_t
{
  time_t created_at;
  uint32_t ticket;
  coin_t coins[MAX_COINS_PER_TICKET];
  char claims[TOTAL_RAIDA_SERVERS];
  uint32_t num_coins;
  // pthread_mutex_t mtx;
  struct ticket_entry_t *next;
};

// Ticket management functions
void check_tickets(void);
int init_ticket_storage(void);
struct ticket_entry_t *get_free_ticket_slot(void);
struct ticket_entry_t *get_ticket_entry(uint32_t);
void unlock_ticket_entry(struct ticket_entry_t *te);

// Statistics and timing
void write_stat(conn_info_t *);

// How many seconds a RAIDA server waits for a response from another RAIDA server
#define RAIDA_SERVER_RCV_TIMEOUT 32

#endif // _PROTOCOL_H