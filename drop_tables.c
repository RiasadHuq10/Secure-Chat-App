#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

#define DATABASE_NAME "./chat.db"  


void drop_tables(sqlite3 *db) {
    char *err_msg = NULL;


    const char *drop_users_table = "DROP TABLE IF EXISTS users;";

    const char *drop_messages_table = "DROP TABLE IF EXISTS messages;";

    if (sqlite3_exec(db, drop_users_table, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "Error dropping users table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return;
    } else {
        printf("Users table dropped successfully (if it existed).\n");
    }

    if (sqlite3_exec(db, drop_messages_table, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "Error dropping messages table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return;
    } else {
        printf("Messages table dropped successfully (if it existed).\n");
    }
}

int main() {
    sqlite3 *db;
    int rc;

    rc = sqlite3_open(DATABASE_NAME, &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return EXIT_FAILURE;
    }

    printf("Connected to database successfully.\n");

    drop_tables(db);

    sqlite3_close(db);
    printf("Database connection closed.\n");

    return EXIT_SUCCESS;
}
