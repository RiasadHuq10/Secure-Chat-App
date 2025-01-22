#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "ui.h"
#include "util.h"
#include "ssl-nonblock.h"
#include <signal.h>
#include <pthread.h>

pthread_mutex_t eof_lock = PTHREAD_MUTEX_INITIALIZER;
struct client_state
{
  struct api_state api;
  int eof;
  struct ui_state ui;
};
struct client_state state;

// void handle_sigint(int sig)
// {
//   api_send("/exit", &state.api);
//   exit(0); // Exit after cleanup
// }

/**
 * @brief Connects to @hostname on port @port and returns the
 *        connection fd. Fails with -1.
 */
static int client_connect(struct client_state *state,
                          const char *hostname, uint16_t port)
{
  int fd;
  struct sockaddr_in addr;

  assert(state);
  assert(hostname);
  printf("connecting to server %s:%u\n", hostname, port);
  fflush(stdout);
  /* look up hostname */
  if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0)
    return -1;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    perror("error: cannot allocate server socket");
    return -1;
  }

  /* connect to server */
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
  {
    perror("error: cannot connect to server");
    close(fd);
    return -1;
  }

  return fd;
}

char *create_packet(int flag, char *msg)
{
  size_t msg_len = strlen(msg);
  char *packet = malloc(msg_len + 2); // 1 for flag, 1 for '\0'
  if (!packet)
  {
    perror("error: malloc failed");
    return NULL;
  }
  snprintf(packet, msg_len + 2, "%d%s", flag, msg); // Format packet
  return packet;
}

int bad_formatting(struct client_state *state)
{
  char *packet = NULL;
  int flag = BADFORMAT;
  char *content = "bad content";
  packet = create_packet(flag, content);

  int send = api_send(packet, &state->api);

  free(packet);
  return send;
}

int unknown_command_input(char *buffer, struct client_state *state)
{

  char *packet = NULL;

  char content[256];
  int flag = UNKNOWN;
  strcpy(content, buffer);
  packet = create_packet(flag, content);
  packet = create_packet(flag, content);

  int send = api_send(packet, &state->api);

  free(packet);
  return send;
}

static int client_process_command(struct client_state *state)
{
  assert(state);

  /* TODO read and handle user command from stdin;
   * set state->eof if there is no more input (read returns zero)
   */
  char buffer[256] = {0};

  if (fgets(buffer, sizeof(buffer), stdin) == NULL)
  {
    pthread_mutex_lock(&eof_lock);
    // printf("we are at eof\n");
    api_send("/exit", &state->api);
    pthread_mutex_unlock(&eof_lock);
    state->eof = 1;
    return 0;
  }
  // printf("buffer at client input %s\n", buffer);
  if (strlen(buffer) <= 0)
    return 0;
  buffer[strlen(buffer) - 1] = '\0';

  int send = api_send(buffer, &state->api);

  // free(packet);
  return send;
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(struct client_state *state, const struct api_msg *msg)
{

  /* TODO handle request and reply to client */
  printf("%s\n", msg->content);
  fflush(stdout);
  return 0;
}

/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
static int handle_server_request(struct client_state *state)
{
  struct api_msg msg;
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, &msg);
  if (r < 0)
    return -1;
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

/**
 * @brief register for multiple IO event, process one
 *        and return. Returns 0 if the event was processed
 *        successfully and -1 otherwise.
 *
 */
static int handle_incoming(struct client_state *state)
{
  int fdmax, r;
  fd_set readfds;

  assert(state);

  /* TODO if we have work queued up, this might be a good time to do it */

  /* TODO ask user for input if needed */

  /* list file descriptors to wait for */
  FD_ZERO(&readfds); // clears up readfds
  FD_SET(STDIN_FILENO, &readfds);
  FD_SET(state->api.fd, &readfds);
  fdmax = state->api.fd;

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
  if (FD_ISSET(STDIN_FILENO, &readfds))
  {
    return client_process_command(state);
  }
  /* TODO once you implement encryption you may need to call 14_has_data
   * here due to buffering (see ssl-nonblock example)
   */
  if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(state->api.ssl))
  {
    return handle_server_request(state);
  }
  return 0;
}

static int client_state_init(struct client_state *state)
{
  /* clear state, invalidate file descriptors */
  memset(state, 0, sizeof(*state));

  /* initialize UI */
  ui_state_init(&state->ui);
  return 0;
}

static int ssl_handshake(struct client_state *state)
{
  /* Initialize SSL context */
  state->api.ctx = SSL_CTX_new(TLS_client_method());
  if (!state->api.ctx)
  {
    fprintf(stderr, "SSL_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return -1; // Return error if SSL_CTX_new fails
  }

  /* Create new SSL structure */
  state->api.ssl = SSL_new(state->api.ctx);
  if (!state->api.ssl)
  {
    fprintf(stderr, "SSL_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    goto error;
  }

  /* configure the socket as non-blocking */
  set_nonblock(state->api.fd);

  /* Associate SSL object with socket file descriptor */
  if (SSL_set_fd(state->api.ssl, state->api.fd) == 0)
  {
    fprintf(stderr, "SSL_set_fd failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    goto error; // Return error if SSL_set_fd fails
  }

  /* Perform the SSL/TLS handshake */
  if (ssl_block_connect(state->api.ssl, state->api.fd) <= 0)
  {
    fprintf(stderr, "SSL_connect failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    goto error;
  }

  return 0;

error:
  if (state->api.ssl)
    SSL_free(state->api.ssl);
  if (state->api.ctx)
    SSL_CTX_free(state->api.ctx);
  return -1;
}

static void client_state_free(struct client_state *state)
{

  /* TODO any additional client state cleanup */

  /* cleanup API state */
  api_state_free(&state->api);

  /* cleanup UI state */
  ui_state_free(&state->ui);
}

static void usage(void)
{
  printf("usage:\n");
  printf("  client host port\n");
  exit(1);
}

int main(int argc, char **argv)
{
  // signal(SIGINT, handle_sigint);
  int fd;
  uint16_t port;
  struct client_state state;
  setvbuf(stdout, NULL, _IONBF, 0);
  /* check arguments */
  if (argc != 3)
    usage();
  if (parse_port(argv[2], &port) != 0)
    usage();

  /* preparations */
  client_state_init(&state);

  /* connect to server */
  fd = client_connect(&state, argv[1], port);
  if (fd < 0)
    return 1;

  /* initialize API */
  api_state_init(&state.api, fd);

  /* TODO any additional client initialization */
  ssl_handshake(&state);

  /* client things */
  while (!state.eof && handle_incoming(&state) == 0)
    ;

  /* clean up */
  /* TODO any additional client cleanup */
  client_state_free(&state);
  close(fd);

  return 0;
}