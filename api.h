#ifndef _API_H_
#define _API_H_

#include <openssl/err.h>
#include <openssl/ssl.h>

enum msg_flag
{
  EXIT,
  LOGIN,
  REGISTER,
  USER,
  MSG,
  PRIVMSG,
  UNKNOWN,
  BADFORMAT,
};

struct api_msg
{
  char *content;
  enum msg_flag flag;
  /* TODO add information about message */
};

struct api_state
{
  int fd;
  int state;
  SSL_CTX *ctx;
  SSL *ssl;
};

int api_recv(struct api_state *state, struct api_msg *msg);
int api_send(char *msg, struct api_state *state);
void api_recv_free(struct api_msg *msg);

void api_state_free(struct api_state *state);
void api_state_init(struct api_state *state, int fd);

/* TODO add API calls to send messages to perform client-server interactions */

#endif /* defined(_API_H_) */
