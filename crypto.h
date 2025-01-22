#ifndef CRYPTO_H_
#define CRYPTO_H_

int hash_password(unsigned char *unhashed_password, char **hashed_password);
int encrypt_message(const unsigned char *plaintext, unsigned char *ciphertext, unsigned char *iv);
unsigned char *parsehex(const char *s, size_t len);
int to_hex(const unsigned char *input, char **output, int length);
int decrypt_message(unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *plaintext);

#endif