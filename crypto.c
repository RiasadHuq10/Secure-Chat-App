#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto.h"

#define KEY_FILE "./serverkeys/random-byte.key"

unsigned char *parsehex(const char *s, size_t len)
{
  /* quick and dirty way to parse hex string to binary data */
  unsigned char *buf = calloc(len, 1);
  for (int i = 0; s[i]; i++)
    buf[i / 2] |= (s[i] % 16 + (s[i] >> 6) * 9) << 4 * (1 - i % 2);
  return buf;
}

// --- GENERATED CODE START ---
// prompt: why do we need to convert to hex if its already a charstring? create a to_hex(unsigned char *encrypted_content, char **encrypted_hex) helper function if needed
// url: https://chatgpt.com/share/674c9a61-7dd4-8007-9a1b-f2b41806e5a8
int to_hex(const unsigned char *input, char **output, int length)
{
  *output = malloc((length * 2) + 1);
  if (!*output)
  {
    fprintf(stderr, "Memory allocation failed for hex conversion\n");
    return -1;
  }

  for (int i = 0; i < length; i++)
  {
    snprintf(*output + (i * 2), 3, "%02x", input[i]);
  }

  return 0;
}
// --- GENERATED CODE END ---

// --- GENERATED CODE START ---
// prompt: use this file as an example on how to use aes (aes.c)
// url: https://chatgpt.com/share/674c9a61-7dd4-8007-9a1b-f2b41806e5a8
static unsigned char *read_key_from_file(const char *filename, size_t *key_len)
{
  FILE *file = fopen(filename, "rb");
  if (!file)
  {
    perror("Failed to open key file");
    exit(EXIT_FAILURE);
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  unsigned char *key = malloc(file_size);
  if (!key)
  {
    perror("Failed to allocate memory for key");
    exit(EXIT_FAILURE);
  }

  fread(key, 1, file_size, file);
  fclose(file);

  *key_len = file_size;
  return key;
}
// --- GENERATED CODE END ---

// --- GENERATED CODE START ---
// prompt: change this code so that it uses the read_key_from_file function to get the key
// url: https://chatgpt.com/share/674c9a61-7dd4-8007-9a1b-f2b41806e5a8
int encrypt_message(const unsigned char *plaintext, unsigned char *ciphertext, unsigned char *iv)
{
  printf("before encryption: %s", plaintext);

  int plaintext_len = strlen((const char *)plaintext);
  size_t key_len;
  unsigned char *key = read_key_from_file(KEY_FILE, &key_len);
  printf("key in enc %s\n", key);
  printf("iv inside the fun\n");
  for (int i = 0; i < 16; i++)
  {
    printf("%02x ", iv[i]);
  }
  printf("\n");

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return -1;

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
  {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  int len;
  int ciphertext_len = 0;

  if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
  {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len += len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
  {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  // unsigned char decrypted_message[EVP_MAX_MD_SIZE];
  printf("ciperlen inside enc %d\n", ciphertext_len);

  return ciphertext_len;
}
// --- GENERATED CODE END ---

int hash_password(unsigned char *unhashed_password, char **hashed_password)
{
  *hashed_password = calloc(EVP_MAX_MD_SIZE * 2 + 1, sizeof(char));

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
  {
    fprintf(stderr, "Failed to create EVP_MD_CTX\n");
    return -1;
  }

  if (!EVP_DigestInit(ctx, EVP_sha256()))
  {
    fprintf(stderr, "Failed to initialize EVP digest\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  unsigned char nonhex_password[EVP_MAX_MD_SIZE];
  if (!EVP_DigestUpdate(ctx, unhashed_password, strlen((const char *)unhashed_password)))
  {
    fprintf(stderr, "Failed to update EVP digest\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  unsigned int hashlen = 0;
  if (!EVP_DigestFinal(ctx, nonhex_password, &hashlen))
  {
    fprintf(stderr, "Failed to finalize EVP digest\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  EVP_MD_CTX_free(ctx);

  for (unsigned int i = 0; i < hashlen; i++)
  {
    sprintf(*hashed_password + (i * 2), "%02x", nonhex_password[i]);
  }

  printf("hex hash: %s\n", *hashed_password);

  return 0;
}
// --- END OF GENERATED CODE ---

// --- GENERATED CODE START ---
// prompt: create a decrypt_message function using static unsigned char *parsehex(const char *s, size_t len)
// url: https://chatgpt.com/share/674c9a61-7dd4-8007-9a1b-f2b41806e5a8
int decrypt_message(unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *plaintext)
{
  size_t key_len;
  printf("ciperlen inside dec %d\n", ciphertext_len);
  unsigned char *key = read_key_from_file(KEY_FILE, &key_len);
  printf("key in dec %s\n", key);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    printf("decrypt error 0\n");
    return -1;
  }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
  {
    printf("decrypt error 1\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  int len;
  int plaintext_len = 0;

  if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
  {
    printf("decrypt error 2\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len += len;

  if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
  {
    printf("decrypt error 3\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}
// --- END OF GENERATED CODE ---