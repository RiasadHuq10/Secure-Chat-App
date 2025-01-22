#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>

void generate_random_key(const char *filename, size_t key_size) {
    unsigned char *key = malloc(key_size);
    if (!key) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    if (RAND_bytes(key, key_size) != 1) {
        fprintf(stderr, "Error generating random key\n");
        free(key);
        exit(EXIT_FAILURE);
    }

    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening file");
        free(key);
        exit(EXIT_FAILURE);
    }

    if (fwrite(key, 1, key_size, file) != key_size) {
        perror("Error writing key to file");
    }

    fclose(file);
    free(key);

    printf("Key of size %zu bytes written to %s\n", key_size, filename);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <filename> <key_size>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filename = argv[1];
    size_t key_size = (size_t)atoi(argv[2]);

    generate_random_key(filename, key_size);

    return 0;
}