#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "ssl-nonblock.h"

#include "api.h"

/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(struct api_state *state, struct api_msg *msg)
{
  char buffer[256];
  int r;

  /* receive the first byte and set it as flag */
  r = ssl_block_read(state->ssl, state->fd, buffer, sizeof(buffer));
  if (r <= 0)
  {
    int err = SSL_get_error(state->ssl, r);
    if (err == SSL_ERROR_ZERO_RETURN)
    {
      return 0;
    }
    else
    {
      return -1;
    }
  }
  buffer[r] = '\0';
  /* allocate memory for the content */
  size_t contentSize = strlen(buffer) + 1;

  msg->content = (char *)malloc(contentSize * sizeof(char));
  if (!msg->content)
  {
    perror("error: malloc failed");
    return -1;
  }
  memcpy(msg->content, buffer, strlen(buffer));

  // strcpy(msg->content, buffer);
  msg->content[strlen(buffer)] = '\0';

  return 1;
}

/**
 * @brief         Send the message
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on error, 0 on success
 */
int api_send(char *msg, struct api_state *state)
{

  assert(state);
  assert(msg);

  ssize_t bytes_sent = ssl_block_write(state->ssl, state->fd, msg, strlen(msg));
  if (bytes_sent < 0)
  {
    perror("error: send failed");
    return -1;
  }

  return 0;
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg)
{

  assert(msg);
  free(msg->content);

  /* TODO clean up state allocated for msg */
}

/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state *state)
{

  assert(state);

  /* TODO clean up API state */
  SSL_shutdown(state->ssl);
  SSL_free(state->ssl);
  SSL_CTX_free(state->ctx);
}

/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state *state, int fd)
{

  assert(state);

  /* initialize to zero */
  memset(state, 0, sizeof(*state));

  /* store connection socket */
  state->fd = fd;

  /* TODO initialize API state */
}
