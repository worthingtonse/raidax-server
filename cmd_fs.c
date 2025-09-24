/* ====================================================
#   Copyright (C) 2023 CloudCoinConsortium
#
#   Author        : Alexander Miroch
#   Email         : alexander.miroch@protonmail.com
#   File Name     : cmd_fs.c
#   Last Modified : 2025-07-23 11:02
#   Describe      : Secure Filesystem Commands with Path Traversal Protection
#
# ====================================================*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h> // For PATH_MAX

#include "protocol.h"
#include "log.h"
#include "commands.h"
#include "db.h"
#include "config.h"
#include "utils.h"
#include "locker.h"
#include "stats.h"

extern struct config_s config;

/*
 * Retrieves an object from the filesystem.
 */
void cmd_get_object(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  char user_path[PATH_MAX];
  char full_user_path[PATH_MAX];
  char resolved_path[PATH_MAX];
  char base_path[PATH_MAX];
  char resolved_base_path[PATH_MAX];
  int rv, fd;
  struct stat st;

  debug("CMD GetObject");

  // Validate request size: 16 (AU) + 1 (min path) + 2 (EOF) = 19 bytes payload
  if (ci->body_size < 19)
  {
    error("Invalid command length for GetObject: %d", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  // Authenticate using the configured admin key
  if (memcmp(&payload[0], config.admin_key, 16) != 0)
  {
    error("Authentication failed for GetObject.");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  // Safely copy the user-provided path from the payload
  int path_len = ci->body_size - 16 - 2; // 16 AU + 2 EOF
  if (path_len >= PATH_MAX)
  {
    error("File path is too long.");
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }
  memcpy(user_path, &payload[16], path_len);
  user_path[path_len] = '\0';

  // ** SECURITY: Path Traversal Prevention **
  // 1. Define the secure base directory.
  snprintf(base_path, sizeof(base_path), "%s/Folders", config.cwd);
  if (realpath(base_path, resolved_base_path) == NULL)
  {
    error("Secure base directory '%s' does not exist or is inaccessible.", base_path);
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  // 2. Construct the full path and resolve it to its canonical form.
  snprintf(full_user_path, sizeof(full_user_path), "%s/%s", resolved_base_path, user_path);
  if (realpath(full_user_path, resolved_path) == NULL)
  {
    error("Failed to resolve path or path does not exist: %s", full_user_path);
    ci->command_status = ERROR_FILE_NOT_EXIST;
    return;
  }

  // 3. Verify that the resolved path is within the secure base directory.
  if (strncmp(resolved_path, resolved_base_path, strlen(resolved_base_path)) != 0)
  {
    error("Path traversal attempt detected. Resolved path '%s' is outside of base '%s'", resolved_path, resolved_base_path);
    ci->command_status = ERROR_ADMIN_AUTH; // Use a generic error to not reveal info
    return;
  }

  debug("Getting object from verified path: %s", resolved_path);

  rv = stat(resolved_path, &st);
  if (rv < 0)
  {
    error("Failed to stat %s: %s", resolved_path, strerror(errno));
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  if (!S_ISREG(st.st_mode))
  {
    error("Path is not a regular file: %s", resolved_path);
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }

  debug("Object size %lld", (long long)st.st_size);

  ci->output_size = st.st_size;
  ci->output = (unsigned char *)malloc(ci->output_size);
  if (ci->output == NULL)
  {
    error("Can't alloc buffer for the response");
    ci->command_status = ERROR_MEMORY_ALLOC;
    return;
  }

  fd = open(resolved_path, O_RDONLY);
  if (fd < 0)
  {
    error("Failed to open file %s: %s", resolved_path, strerror(errno));
    free(ci->output);
    ci->output = NULL;
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  rv = read(fd, ci->output, ci->output_size);
  close(fd);

  if (rv < 0 || rv != ci->output_size)
  {
    error("Failed to read file %s: %s", resolved_path, strerror(errno));
    free(ci->output);
    ci->output = NULL;
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD GetObject finished");
}

/*
 * Stores an object in the filesystem.
 */
void cmd_put_object(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  char user_path[PATH_MAX];
  char full_user_path[PATH_MAX];
  char resolved_path[PATH_MAX];
  char base_path[PATH_MAX];
  char resolved_base_path[PATH_MAX];
  int rv, fd;
  uint32_t file_size;
  int filename_length;
  unsigned char *file_content;

  debug("CMD PutObject");

  // Validate minimum possible packet size
  if (ci->body_size < (16 + 4 + 1 + 1 + 0 + 2))
  { // AU+size+nullterm+min_filename+content+EOF
    error("Invalid command length for PutObject: %d", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  if (memcmp(&payload[0], config.admin_key, 16) != 0)
  {
    error("Authentication failed for PutObject.");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  file_size = get_u32(&payload[16]);
  debug("File size from payload: %u", file_size);

  // The filename is null-terminated within the payload
  filename_length = strnlen((char *)&payload[20], PATH_MAX);
  if (filename_length == 0 || filename_length >= PATH_MAX)
  {
    error("Invalid filename length.");
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }
  strncpy(user_path, (char *)&payload[20], PATH_MAX - 1);
  user_path[PATH_MAX - 1] = '\0';

  file_content = &payload[20 + filename_length + 1];

  // Verify that the total body size matches the expected size
  if (ci->body_size != (16 + 4 + filename_length + 1 + file_size + 2))
  {
    error("Body size mismatch. Expected %d, got %d", (16 + 4 + filename_length + 1 + file_size + 2), ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  // ** SECURITY: Path Traversal Prevention **
  // 1. Define and resolve the secure base directory.
  snprintf(base_path, sizeof(base_path), "%s/Folders", config.cwd);
  if (realpath(base_path, resolved_base_path) == NULL)
  {
    error("Secure base directory '%s' does not exist or is inaccessible.", base_path);
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  // 2. Construct the full path and resolve it to its canonical form.
  snprintf(full_user_path, sizeof(full_user_path), "%s/%s", resolved_base_path, user_path);
  if (realpath(full_user_path, resolved_path) == NULL)
  {
    // If the file doesn't exist, realpath fails. We need to resolve the directory part.
    char *last_slash = strrchr(full_user_path, '/');
    if (last_slash)
    {
      *last_slash = '\0';
      if (realpath(full_user_path, resolved_path) == NULL)
      {
        error("Target directory does not exist or is invalid: %s", full_user_path);
        ci->command_status = ERROR_FILE_NOT_EXIST;
        return;
      }
      *last_slash = '/'; // Restore path
    }
    else
    {
      // Writing to the root of the base directory
      strncpy(resolved_path, resolved_base_path, PATH_MAX - 1);
    }
  }

  // 3. Verify that the resolved path is within the secure base directory.
  if (strncmp(resolved_path, resolved_base_path, strlen(resolved_base_path)) != 0)
  {
    error("Path traversal attempt detected for PutObject.");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  debug("Writing %u bytes to verified path: %s", file_size, full_user_path);

  fd = open(full_user_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
  {
    error("Failed to open file %s for writing: %s", full_user_path, strerror(errno));
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  rv = write(fd, file_content, file_size);
  close(fd);

  if (rv < 0 || rv != file_size)
  {
    error("Failed to write file %s: %s", full_user_path, strerror(errno));
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD PutObject finished");
}

/*
 * Removes an object from the filesystem.
 */
void cmd_rm_object(conn_info_t *ci)
{

  if (ci->body == NULL)
  {
    error("Command received with no body. Rejecting.");
    ci->command_status = ERROR_EMPTY_REQUEST;
    return;
  }
  unsigned char *payload = get_body_payload(ci);
  char user_path[PATH_MAX];
  char full_user_path[PATH_MAX];
  char resolved_path[PATH_MAX];
  char base_path[PATH_MAX];
  char resolved_base_path[PATH_MAX];
  int rv;

  debug("CMD RmObject");

  if (ci->body_size < 19)
  {
    error("Invalid command length for RmObject: %d", ci->body_size);
    ci->command_status = ERROR_INVALID_PACKET_LENGTH;
    return;
  }

  if (memcmp(&payload[0], config.admin_key, 16) != 0)
  {
    error("Authentication failed for RmObject.");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  int path_len = ci->body_size - 16 - 2;
  if (path_len >= PATH_MAX)
  {
    error("File path is too long.");
    ci->command_status = ERROR_INVALID_PARAMETER;
    return;
  }
  memcpy(user_path, &payload[16], path_len);
  user_path[path_len] = '\0';

  // ** SECURITY: Path Traversal Prevention **
  snprintf(base_path, sizeof(base_path), "%s/Folders", config.cwd);
  if (realpath(base_path, resolved_base_path) == NULL)
  {
    error("Secure base directory '%s' does not exist or is inaccessible.", base_path);
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  snprintf(full_user_path, sizeof(full_user_path), "%s/%s", resolved_base_path, user_path);
  if (realpath(full_user_path, resolved_path) == NULL)
  {
    error("File to remove does not exist or path is invalid: %s", full_user_path);
    ci->command_status = ERROR_FILE_NOT_EXIST;
    return;
  }

  if (strncmp(resolved_path, resolved_base_path, strlen(resolved_base_path)) != 0)
  {
    error("Path traversal attempt detected for RmObject.");
    ci->command_status = ERROR_ADMIN_AUTH;
    return;
  }

  debug("Removing verified object: %s", resolved_path);
  rv = remove(resolved_path);
  if (rv < 0)
  {
    error("Failed to remove file: %s", strerror(errno));
    ci->command_status = ERROR_FILESYSTEM;
    return;
  }

  ci->command_status = (char)STATUS_SUCCESS;
  debug("CMD RmObject finished");
}

/*
 * Helper function to get a cryptographic key from a specific file.
 * This is used internally by other commands.
 */
char *get_crypto_key(char *ticker, int *size)
{
  char key_path[PATH_MAX];
  char resolved_path[PATH_MAX];
  char base_path[PATH_MAX];
  char resolved_base_path[PATH_MAX];
  struct stat st;
  char *output;
  ssize_t rv;
  int fd;

  debug("Looking for crypto key for ticker: %s", ticker);

  // ** SECURITY: Path Traversal Prevention **
  snprintf(base_path, sizeof(base_path), "%s/Folders", config.cwd);
  if (realpath(base_path, resolved_base_path) == NULL)
  {
    warning("Secure base directory '%s' does not exist.", base_path);
    return NULL;
  }

  snprintf(key_path, sizeof(key_path), "%s/%s", resolved_base_path, ticker);
  if (realpath(key_path, resolved_path) == NULL)
  {
    warning("Cannot resolve key file path: %s", key_path);
    return NULL;
  }

  if (strncmp(resolved_path, resolved_base_path, strlen(resolved_base_path)) != 0)
  {
    warning("Path traversal attempt for get_crypto_key detected.");
    return NULL;
  }

  debug("Checking key path: %s", resolved_path);

  if (stat(resolved_path, &st) < 0)
  {
    warning("Failed to stat key file %s: %s", resolved_path, strerror(errno));
    return NULL;
  }

  if (!S_ISREG(st.st_mode))
  {
    warning("Key path is not a regular file.");
    return NULL;
  }

  output = (char *)malloc(st.st_size);
  if (output == NULL)
  {
    error("Can't alloc buffer for the key");
    return NULL;
  }

  fd = open(resolved_path, O_RDONLY);
  if (fd < 0)
  {
    error("Failed to open key file %s: %s", resolved_path, strerror(errno));
    free(output);
    return NULL;
  }

  rv = read(fd, output, st.st_size);
  close(fd);

  if (rv != st.st_size)
  {
    error("Failed to read key file %s: %s", resolved_path, strerror(errno));
    free(output);
    return NULL;
  }

  *size = st.st_size;
  debug("Read %d bytes of %s key", (int)rv, ticker);
  return output;
}
