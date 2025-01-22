#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>
#include <ctype.h>

#include "api.h"
#include "util.h"
#include "worker.h"
#include "ssl-nonblock.h"
#include "database.h"
#include "crypto.h"

// void reduce_spaces(char *str)
// {
//   char *read = str, *write = str;
//   int space_found = 0;

//   while (*read)
//   {
//     if (isspace((unsigned char)*read))
//     {
//       if (!space_found)
//       {
//         *write++ = ' '; // Write a single space
//         space_found = 1;
//       }
//     }
//     else
//     {
//       *write++ = *read; // Copy non-space characters
//       space_found = 0;  // Reset space flag
//     }
//     read++;
//   }

//   *write = '\0'; // Null-terminate the result
// }

void find_content(char *str)
{
}

struct worker_state
{
  struct api_state api;
  int eof;
  int server_fd; /* server <-> worker bidirectional notification channel */
  int server_eof;
  /* TODO worker state variables go here */
  char *uid;
  time_t lastRefresh;
};

/**
 * @brief Returns 1 (true) if
  state->uid is non-NULL
  Returns 0 (false) otherwise.
 */
static int is_logged_in(struct worker_state *state)
{
  return state->uid != NULL && state->uid[0] != '\0';
}

static int send_unread_messages(struct worker_state *state)
{
  printf("current lastRefresh: %s", ctime(&state->lastRefresh));
  if (!is_logged_in(state))
  {
    printf("Not logged in for s2w\n");
    return 0;
  }

  char buff[160];
  sqlite3_stmt *stmt;
  // api_send("This is a test at s2wnotif", &state->api);
  if (get_messages(&stmt, state->uid, &(state->lastRefresh)) != 0)
  {
    return -1; // Error occurred in database operation
  }

  while (sqlite3_step(stmt) == SQLITE_ROW)
  {
    const char *timestamp = (const char *)sqlite3_column_text(stmt, 5);

    // Update lastRefresh
    struct tm tm = {0};
    if (sscanf(timestamp, "%4d-%2d-%2d %2d:%2d:%2d",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6)
    {
      tm.tm_year -= 1900;
      tm.tm_mon -= 1;
      time_t messageTime = mktime(&tm);
      if (messageTime > state->lastRefresh)
      {
        state->lastRefresh = messageTime;
      }
    }
    else
    {
      fprintf(stderr, "Failed to parse timestamp: %s\n", timestamp);
    }

    printf("updated lastRefresh: %s", ctime(&state->lastRefresh));

    const char *sender_id = (const char *)sqlite3_column_text(stmt, 0);
    const char *recipient_id = (const char *)sqlite3_column_text(stmt, 1);
    const char *is_encrypted = (const char *)sqlite3_column_text(stmt, 3);
    // const char *iv_hex = (const char *)sqlite3_column_text(stmt, 4);
    if (is_encrypted && strcmp(is_encrypted, "1") == 0)
    {
      unsigned char decrypted_message[EVP_MAX_MD_SIZE];

      int ciphertext_len = sqlite3_column_bytes(stmt, 2);
      int iv_len = sqlite3_column_bytes(stmt, 4);
      unsigned char *ciphertext = malloc(ciphertext_len);
      unsigned char *iv = malloc(iv_len);
      memcpy(ciphertext, sqlite3_column_blob(stmt, 2), ciphertext_len);
      memcpy(iv, sqlite3_column_blob(stmt, 4), iv_len);
      printf("iv in decryption \n");
      for (int i = 0; i < 16; i++)
      {
        printf("%02x ", iv[i]);
      }
      printf("\n");
      printf("retrieved iv_len %d\n", iv_len);
      printf("retrieved cipherlen decrypt %d\n", ciphertext_len);
      printf("content dec %s\n", ciphertext);
      int decrypt_content_length = decrypt_message(ciphertext, ciphertext_len, iv, decrypted_message);
      if (decrypt_content_length <= 0)
      {
        fprintf(stderr, "Failed to decrypt message\n");
        continue;
      }
      decrypted_message[decrypt_content_length] = '\0';
      // content = (const char *)decrypted_message;
      printf("decrypt successfull\n");
      snprintf(buff, sizeof(buff), "%s %s: @%s %s",
               timestamp ? timestamp : "NULL",
               sender_id ? sender_id : "Unknown",
               recipient_id,
               decrypted_message);
      free(ciphertext);
      free(iv);
    }
    else
    {
      const char *content = (const char *)sqlite3_column_text(stmt, 2);
      snprintf(buff, sizeof(buff), "%s %s: %s",
               timestamp ? timestamp : "NULL",
               sender_id ? sender_id : "Unknown",

               content ? content : "NULL");
    }

    api_send(buff, &state->api); // Send the notification
  }

  sqlite3_finalize(stmt);
  return 0;
}
//-- -GENERATED CODE END-- -

// url: https://chatgpt.com/share/674c9a61-7dd4-8007-9a1b-f2b41806e5a8
/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */

static int handle_s2w_notification(struct worker_state *state)
{
  send_unread_messages(state);

  printf("Done with handle_s2w_notification\n");
  return 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
/* TODO call this function to notify other workers through server */
__attribute__((unused)) static int notify_workers(struct worker_state *state)
{
  char buf = 0;
  ssize_t r;

  /* we only need to send something to notify the other workers,
   * data does not matter
   */
  r = write(state->server_fd, &buf, sizeof(buf));
  if (r < 0 && errno != EPIPE)
  {
    perror("error: write of server_fd failed");
    return -1;
  }

  return 0;
}

static int register_user(char *user_id, char *unhashed_password, struct worker_state *state)
{
  if (is_logged_in(state))
  {
    printf("inside error\n");
    api_send("error: command not currently available", &state->api);
    return 0;
  }
  char *buff = NULL;
  // printf("state->uid: %s\n", state->uid);
  // printf("is logged in: %d\n", is_logged_in(state));

  char *password = NULL;

  hash_password((unsigned char *)unhashed_password, &password);

  if (insert_user(&buff, user_id, password) == 0)
  {
    state->uid = strdup(user_id);
  }

  api_send(buff, &state->api);
  free(password);
  free(buff);

  return 0;
}

static int login_user(char *user_id, char *unhashed_password, struct worker_state *state)
{
  if (is_logged_in(state))
  {
    api_send("error: command not currently available", &state->api);
    return 0;
  }

  char *buff = NULL;

  char *password = NULL;

  hash_password((unsigned char *)unhashed_password, &password);

  int login_result = search_user(&buff, user_id, password);
  printf("login result : %d\n", login_result);

  if (login_result == 0)
  {
    state->uid = strdup(user_id);
  }

  api_send(buff, &state->api);
  free(password);
  free(buff);

  return 0;
}

static int list_users(const struct api_msg *msg, struct worker_state *state)
{
  char buff[160];

  if (!is_logged_in(state))
  {
    snprintf(buff, sizeof(buff), "error: command not currently available");
    api_send(buff, &state->api);
    return 0;
  }

  sqlite3_stmt *stmt;

  if (get_user_list(&stmt) != 0)
  {
    return -1;
  }

  int user_found = 0;
  while (sqlite3_step(stmt) == SQLITE_ROW)
  {
    const unsigned char *user_id = sqlite3_column_text(stmt, 0);
    if (user_id)
    {
      user_found = 1;

      snprintf(buff, sizeof(buff), "%s", user_id);
      api_send(buff, &state->api);
    }
  }

  sqlite3_finalize(stmt);

  if (!user_found)
  {
    snprintf(buff, sizeof(buff), "No registered users found.");
    api_send(buff, &state->api);
  }

  return 0;
}

// --- GENERATED CODE START ---
// prompt: Refactor this code so that the sql parts are separated into functions in database.c
// url: https://chatgpt.com/share/674c9a61-7dd4-8007-9a1b-f2b41806e5a8
static int save_to_db(char *recipient_id, char *msg, struct worker_state *state)
{
  if (!is_logged_in(state))
  {
    api_send("error: command not currently available", &state->api);
    return 0;
  }

  time_t now;
  struct tm *local;
  char dateTime[20];

  time(&now);
  local = localtime(&now);
  strftime(dateTime, sizeof(dateTime), "%Y-%m-%d %H:%M:%S", local);
  if (recipient_id != NULL)
  {

    // Check if the user exists
    if (!user_exists(recipient_id))
    {
      api_send("error: user not found", &state->api);
      return 0;
    }

    unsigned char encrypted_content[EVP_MAX_MD_SIZE];
    unsigned char iv[16];
    RAND_bytes(iv, 16);
    printf("iv before encryption\n");
    for (int i = 0; i < 16; i++)
    {
      printf("%02x ", iv[i]);
    }
    printf("\n");
    int encrypted_content_length = 0;
    printf("tryinf to encrypt \n");
    encrypted_content_length = encrypt_message((const unsigned char *)msg, encrypted_content, iv);

    if (encrypted_content_length <= 0)
    {
      printf("encryptuon fail\n");
      return -1;
    }
    printf("retrieved cipherlen encrypt %d\n", encrypted_content_length);

    printf("trying to inseert\n");
    printf("content enc %s\n", encrypted_content);
    // encrypt_message[encrypted_content_length] = '\0';
    if (insert_private_message(state->uid, recipient_id, (char *)encrypted_content, (const char *)iv, dateTime, encrypted_content_length) != 0)
    {
      perror("insertion failed\n");
      // free(encrypted_content);
      return -1;
    }
    // printf("content enc %s\n", encrypted_content);

    // free(encrypted_content);
  }
  else
  {
    // Insert the public message
    if (insert_public_message(state->uid, msg, dateTime) != 0)
    {
      return -1;
    }
  }

  return 0;
}

int exit_user(struct worker_state *state)
{
  if (!is_logged_in(state))
    return 0;
  sqlite3 *db;
  char *err_msg = NULL;
  int rc;
  char sql[256];

  rc = sqlite3_open("./chat.db", &db);
  if (rc != SQLITE_OK)
  {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    return -1;
  }
  sqlite3_busy_timeout(db, 5000);
  snprintf(sql, sizeof(sql),
           "UPDATE users SET devices = devices - 1 WHERE user_id = '%s' AND devices > 0;", state->uid);

  rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
  if (rc != SQLITE_OK)
  {
    fprintf(stderr, "SQL error: %s\n", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(db);
    return -1;
  }

  sqlite3_close(db);

  printf("User '%s' has been logged out, and device count has been updated.\n", state->uid);
  free(state->uid);
  state->uid = NULL;

  sqlite3_close(db);
  return 0;
}

int unknown_command(const struct api_msg *msg, struct worker_state *state)
{
  char buff[160];
  char *command = strtok(msg->content, " ");
  snprintf(buff, sizeof(buff), "error: unknown command %s", command);
  api_send(buff, &state->api);
  return 0;
}
int bad_format(const struct api_msg *msg, struct worker_state *state)
{
  char buff[160];
  snprintf(buff, sizeof(buff), "error: invalid command format");
  api_send(buff, &state->api);
  return 0;
}
int check_exit(const struct api_msg *msg, char *buffer, struct worker_state *state)
{
  if (strlen(buffer) > 5 && buffer[5] != ' ')
  {
    return unknown_command(msg, state);
  }
  int spaces = 0;
  for (int i = 0; i < strlen(buffer); i++)
  {
    if (buffer[i] == ' ')
    {
      spaces++;
    }
  }
  if (spaces != 0)
  {
    return bad_format(msg, state);
  }

  printf("Command: exit\n");
  exit_user(state);
  state->eof = 1;
  return 0;
}

int parse_username_password(char *username, char *password, char *buffer)
{
  while (*buffer != ' ')
  {
    buffer++;
  }
  printf("%s\n", buffer);
  while (*buffer == ' ')
  {
    buffer++;
  }
  printf("%s\n", buffer);
  int index = 0;
  while (*buffer != ' ')
  {
    // printf("%s\n", buffer);
    *(username + index) = *buffer;
    buffer++;
    index++;
  }
  username[index] = '\0';

  while (*buffer == ' ')
  {
    buffer++;
  }
  index = 0;

  while (*buffer != '\0')
  {
    *(password + index) = *buffer;
    buffer++;
    index++;
  }
  password[index] = '\0';

  printf("Command: register\nUsername: %s\nPassword: %s\n", username, password);
  return 0;
}

int check_users(const struct api_msg *msg, char *buffer, struct worker_state *state)
{
  if (strlen(buffer) > 6 && buffer[6] != ' ')
  {
    return unknown_command(msg, state);
  }

  int spaces = 0;
  for (int i = 0; i < strlen(buffer) - 1; i++)
  {
    if (buffer[i] != ' ' && buffer[i + 1] == ' ')
    {
      spaces++;
    }
  }
  if (spaces != 0)
  {
    return bad_format(msg, state);
  }
  list_users(msg, state);
  return 0;
}

int check_register(const struct api_msg *msg, char *buffer, struct worker_state *state)
{
  if (strlen(buffer) == 9)
  {
    bad_format(msg, state);
    return 0;
  }
  if (buffer[9] != ' ')
  {
    unknown_command(msg, state);
    return 0;
  }
  int spaces = 0;

  for (int i = 0; i < strlen(buffer) - 1; i++)
  {
    if (buffer[i] == ' ' && buffer[i + 1] != ' ')
    {
      spaces++;
    }
  }
  if (spaces != 2)
  {
    bad_format(msg, state);
    return 0;
  };
  if (is_logged_in(state))
  {
    // printf("inside error\n");
    api_send("error: command not currently available", &state->api);
    return 0;
  }

  char *username = calloc(sizeof(buffer), sizeof(char));
  char *password = calloc(sizeof(buffer), sizeof(char));

  parse_username_password(username, password, buffer);

  register_user(username, password, state);
  free(username);
  free(password);
  printf("no issue here\n");
  // notify_workers(state);
  send_unread_messages(state);
  return 0;
}

int check_login(const struct api_msg *msg, char *buffer, struct worker_state *state)
{
  if (strlen(buffer) == 6)
  {
    bad_format(msg, state);
    return 0;
  }
  if (buffer[6] != ' ')
  {
    unknown_command(msg, state);
    return 0;
  }
  int spaces = 0;

  for (int i = 0; i < strlen(buffer) - 1; i++)
  {
    if (buffer[i] != ' ' && buffer[i + 1] == ' ')
    {
      spaces++;
    }
  }
  if (spaces != 2)
  {
    bad_format(msg, state);
    return 0;
  };
  if (is_logged_in(state))
  {
    // printf("inside error\n");
    api_send("error: command not currently available", &state->api);
    return 0;
  }
  char *username = calloc(sizeof(buffer), sizeof(char));
  char *password = calloc(sizeof(buffer), sizeof(char));

  parse_username_password(username, password, buffer);

  printf("Command: login\nUsername: %s\nPassword: %s\n", username, password);

  login_user(username, password, state);
  free(username);
  free(password);
  // notify_workers(state);
  send_unread_messages(state);
  return 0;
}

int check_private_message(const struct api_msg *msg, char *buffer, struct worker_state *state)
{
  if (strlen(buffer) == 1)
  {

    return bad_format(msg, state);
  }
  if (buffer[1] == ' ')
  {

    return bad_format(msg, state);
  }
  int spaces = 0;
  for (int i = 0; i < strlen(buffer); i++)
  {
    if (buffer[i] == ' ')
    {
      spaces++;
    }
  }
  if (spaces == 0)
  {
    printf("3\n");

    return bad_format(msg, state);
  }
  if (!is_logged_in(state))
  {
    // printf("inside error\n");
    api_send("error: command not currently available", &state->api);
    return 0;
  }
  buffer++;
  char *username = calloc(sizeof(buffer), sizeof(char));
  int index = 0;
  while (*buffer != ' ')
  {
    *(username + index) = *buffer;
    buffer++;
    index++;
  }
  username[index] = '\0';
  while (*buffer == ' ')
  {
    buffer++;
  }

  // buffer = buffer + 1 + strlen(username);
  printf("uid %s\n", username);
  printf("buffer %s\n", buffer);

  save_to_db(username, buffer, state);
  free(username);
  notify_workers(state);
  return 0;
}

int check_public_message(const struct api_msg *msg, char *buffer, struct worker_state *state)
{
  if (!is_logged_in(state))
  {
    // printf("inside error\n");
    api_send("error: command not currently available", &state->api);
    return 0;
  }
  save_to_db(NULL, buffer, state);
  notify_workers(state);
  return 0;
}

int strip_buffer(const struct api_msg *msg, char *buffer, int content_length)
{

  return 0;
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */

static int execute_request(
    struct worker_state *state,
    const struct api_msg *msg)
{

  if (msg->content == NULL)
  {
    fprintf(stderr, "Error: msg->content is NULL\n");
    return -1;
  }

  printf("executing request\n");

  size_t content_length = strlen(msg->content) + 1;
  char *stored_buffer = (char *)malloc(content_length);

  if (stored_buffer == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for buffer\n");
    return -1;
  }
  char *buffer = stored_buffer;
  strncpy(buffer, msg->content, content_length - 1);
  buffer[content_length - 1] = '\0';

  printf("worker received message: %s\n", msg->content);
  printf("worker buffer message: %s\n", buffer);

  // Trim leading spaces
  while (buffer[0] == ' ')
  {
    buffer++;
  }

  // Trim trailing spaces
  char *end = buffer + strlen(buffer) - 1;
  while (end >= buffer && *end == ' ')
  {
    *end = '\0';
    end--;
  }
  strip_buffer(msg, buffer, content_length);

  if (strncmp(buffer, "/exit", 5) == 0)
  {
    check_exit(msg, buffer, state);
    free(stored_buffer);
    return 0;
  }
  else if (strncmp(buffer, "/users", 6) == 0)
  {
    check_users(msg, buffer, state);
    free(stored_buffer);
    return 0;
  }
  else if (strncmp(buffer, "/register", 9) == 0)
  {
    check_register(msg, buffer, state);
    free(stored_buffer);
    return 0;
  }
  else if (strncmp(buffer, "/login", 6) == 0)
  {
    check_login(msg, buffer, state);
    free(stored_buffer);
    return 0;
  }
  else if (buffer[0] == '/')
  {
    return unknown_command(msg, state);
    free(stored_buffer);
    return 0;
  }
  else if (buffer[0] == '@')
  {
    return check_private_message(msg, buffer, state);
    free(stored_buffer);
    return 0;
  }
  else
  {
    return check_public_message(msg, buffer, state);
    free(stored_buffer);
    return 0;
  }

  free(stored_buffer);
  return 0;
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state)
{

  struct api_msg msg;
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, &msg);

  if (r < 0)
  {
    state->eof = 1;
    return -1;
  }

  if (r == 0)
  {
    state->eof = 1;
    return 0;
  }

  /* execute request */
  if (execute_request(state, &msg) != 0)
  {
    success = 0;
  }

  /* clean up state associated with the message */
  api_recv_free(&msg);

  return success ? 0 : -1;
}

static int handle_s2w_read(struct worker_state *state)
{
  char buf[256];
  ssize_t r;

  /* notification from the server that the workers must notify their clients
   * about new messages; these notifications are idempotent so the number
   * does not actually matter, nor does the data sent over the pipe
   */
  errno = 0;
  r = read(state->server_fd, buf, sizeof(buf));
  if (r < 0)
  {
    perror("error: read server_fd failed");
    return -1;
  }
  if (r == 0)
  {
    state->server_eof = 1;
    return 0;
  }

  /* notify our client */
  if (handle_s2w_notification(state) != 0)
    return -1;

  return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state *state)
{
  int fdmax, r, success = 1;
  fd_set readfds;

  assert(state);

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  /* wake on incoming messages from client */
  FD_SET(state->api.fd, &readfds);
  /* wake on incoming server notifications */
  if (!state->server_eof)
    FD_SET(state->server_fd, &readfds);
  fdmax = max(state->api.fd, state->server_fd);

  /* wait for at least one to become ready */
  r = select(fdmax + 1, &readfds, NULL, NULL, NULL);
  if (r < 0)
  {
    if (errno == EINTR)
      return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  /* TODO once you implement encryption you may need to call ssl_has_data
   * here due to buffering (see ssl-nonblock example)
   */
  if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(state->api.ssl))
  {
    printf("going to handle_client_request\n");
    if (handle_client_request(state) != 0)
      success = 0;
  }
  if (FD_ISSET(state->server_fd, &readfds))
  {
    printf("going to handle_s2w_read\n");
    if (handle_s2w_read(state) != 0)
      success = 0;
  }
  printf("success in handle_incoming %d\n", success);
  return success ? 0 : -1;
}

static int ssl_handshake(struct worker_state *state)
{
  printf("begin handshake\n");
  state->api.ctx = SSL_CTX_new(TLS_server_method());
  if (!state->api.ctx)
  {
    perror("SSL_CTX_new failed");
    return -1;
  }

  state->api.ssl = SSL_new(state->api.ctx);
  if (!state->api.ssl)
  {
    perror("SSL_new failed");
    return -1;
  }

  int cert_load_status = SSL_use_certificate_file(state->api.ssl, "./serverkeys/server-key-cert.pem", SSL_FILETYPE_PEM);
  if (cert_load_status <= 0)
  {
    perror("SSL_use_certificate_file failed");
    return -1;
  }

  int key_load_status = SSL_use_PrivateKey_file(state->api.ssl, "./serverkeys/server-key.pem", SSL_FILETYPE_PEM);
  if (key_load_status <= 0)
  {
    perror("SSL_use_PrivateKey_file failed");
    return -1;
  }

  if (!SSL_check_private_key(state->api.ssl))
  {
    perror("SSL_check_private_key failed");
    return -1;
  }

  /* set up SSL connection with client */
  set_nonblock(state->api.fd);

  SSL_set_fd(state->api.ssl, state->api.fd);
  int ssl_accept_status = ssl_block_accept(state->api.ssl, state->api.fd);
  if (ssl_accept_status <= 0)
  {
    perror("SSL_accept failed");
    return -1;
  }

  printf("handshake successful\n");

  return 0;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param pipefd_w2s   pipe to notify server (write something to notify)
 * @param pipefd_s2w   pipe to be notified by server (can read when notified)
 *
 */
static int worker_state_init(
    struct worker_state *state,
    int connfd,
    int server_fd)
{

  /* initialize */
  memset(state, 0, sizeof(*state));
  state->server_fd = server_fd;
  state->lastRefresh = 0;

  /* set up API state */
  api_state_init(&state->api, connfd);

  /* TODO any additional worker state initialization */
  ssl_handshake(state);

  return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(
    struct worker_state *state)
{
  /* TODO any additional worker state cleanup */

  /* clean up API state */
  api_state_free(&state->api);

  /* close file descriptors */
  close(state->server_fd);
  close(state->api.fd);
}

/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket
 * @param pipefd_w2s   File descriptor for pipe to send notifications
 *                     from worker to server
 * @param pipefd_s2w   File descriptor for pipe to send notifications
 *                     from server to worker
 */
__attribute__((noreturn)) void worker_start(
    int connfd,
    int server_fd)
{
  struct worker_state state;
  int success = 1;

  /* initialize worker state */
  if (worker_state_init(&state, connfd, server_fd) != 0)
  {
    goto cleanup;
  }
  /* TODO any additional worker initialization */

  /* handle for incoming requests */
  while (!state.eof)
  {
    if (handle_incoming(&state) != 0)
    {
      success = 0;
      break;
    }
  }

cleanup:
  /* cleanup worker */
  /* TODO any additional worker cleanup */
  worker_state_free(&state);

  exit(success ? 0 : 1);
}
