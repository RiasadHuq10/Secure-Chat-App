#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "worker.h"
#include "database.h"

#define DATABASE_NAME "./chat.db"

void create_tables(sqlite3 *db)
{
    char *err_msg = NULL;

    const char *create_users_table =
        "CREATE TABLE IF NOT EXISTS users ("
        "user_id VARCHAR PRIMARY KEY, "
        "password VARCHAR, "
        "devices INTEGER NOT NULL);";

    const char *create_messages_table =
        "CREATE TABLE IF NOT EXISTS messages ("
        "id INTEGER PRIMARY KEY, "
        "sender_id VARCHAR NOT NULL, "
        "recipient_id VARCHAR, "
        "content BLOB NOT NULL, "
        "is_encrypted BOOLEAN NOT NULL, "
        "iv BLOB, "
        "timestamp DATETIME NOT NULL, "
        "FOREIGN KEY (sender_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE, "
        "FOREIGN KEY (recipient_id) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE);";

    if (sqlite3_exec(db, create_users_table, 0, 0, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error creating users table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return;
    }
    else
    {
        printf("Users table created successfully (or already exists).\n");
    }

    if (sqlite3_exec(db, create_messages_table, 0, 0, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error creating messages table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return;
    }
    else
    {
        printf("Messages table created successfully (or already exists).\n");
    }
}

int setup_db()
{
    sqlite3 *db;
    int rc;

    rc = sqlite3_open(DATABASE_NAME, &db);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return EXIT_FAILURE;
    }

    printf("Connected to database successfully.\n");

    create_tables(db);

    sqlite3_close(db);
    printf("Database connection closed.\n");

    return EXIT_SUCCESS;
}

// --- GENERATED CODE START ---
// prompt: Refactor this code so that the sql parts are separated into functions in database.c
// url: https://chatgpt.com/share/674c9a61-7dd4-8007-9a1b-f2b41806e5a8
int insert_public_message(const char *sender_id, const char *content, const char *timestamp)
{
    sqlite3 *db;
    char *err_msg = NULL;
    char sql[512];

    int rc = sqlite3_open("./chat.db", &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);

    snprintf(sql, sizeof(sql),
             "INSERT INTO messages (sender_id, recipient_id, content, is_encrypted, iv, timestamp) "
             "VALUES ('%s', NULL, '%s', FALSE, NULL, '%s');",
             sender_id, content, timestamp);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }

    sqlite3_close(db);
    return 0;
}

int insert_private_message(const char *sender_id, const char *recipient_id, const char *content, const char *iv, const char *timestamp, int content_len)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    // char *err_msg = NULL;
    //  char sql[512];
    const char *sql =
        "INSERT INTO messages (sender_id, recipient_id, content, is_encrypted, iv, timestamp) "
        "VALUES (?, ?, ?, TRUE, ?, ?);";
    int rc = sqlite3_open("./chat.db", &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    // snprintf(sql, sizeof(sql),
    //          "INSERT INTO messages (sender_id, recipient_id, content, is_encrypted, iv, timestamp) "
    //          "VALUES ('%s', '%s', '%s', TRUE, '%s', '%s');",
    //          sender_id, recipient_id, content, iv, timestamp);

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, sender_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, recipient_id, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, content, content_len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, iv, 16, SQLITE_STATIC); // Assuming IV is 16 bytes
    sqlite3_bind_text(stmt, 5, timestamp, -1, SQLITE_STATIC);

    // Execute the statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }

    // Finalize and clean up
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}
// --- GENERATED CODE END

// --- GENERATED CODE START ---
// prompt: int user_exists(const char *recipient_id); create this function
// url: https://chatgpt.com/share/674c9a61-7dd4-8007-9a1b-f2b41806e5a8
int user_exists(const char *recipient_id)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result = 0; // 0 means "user does not exist", 1 means "user exists"
    int rc;

    // Open the database connection
    rc = sqlite3_open("chat.db", &db);
    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return -1; // Return -1 for database errors
    }

    // Prepare the SQL statement
    const char *sql = "SELECT 1 FROM users WHERE user_id = ? LIMIT 1";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    // Bind the recipient_id to the parameter in the SQL statement
    sqlite3_bind_text(stmt, 1, recipient_id, -1, SQLITE_STATIC);

    // Execute the statement and check if a row is returned
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        result = 1; // User exists
    }
    else
    {
        result = 0; // User does not exist
    }

    // Finalize and close
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return result;
}
// --- GENERATED CODE END ---

int get_messages(sqlite3_stmt **stmt, char *uid, time_t *lastRefresh)
{
    sqlite3 *db;
    char sql[512];
    /* const char *sql = "SELECT sender_id, recipient_id, content, is_encrypted, timestamp, id "
                      "FROM messages "
                      "WHERE (recipient_id = ? OR recipient_id IS NULL) AND (sender_id != ?) AND timestamp > ?"
                      "ORDER BY timestamp;";
   */
    char lastRefreshStr[20];
    strftime(lastRefreshStr, sizeof(lastRefreshStr), "%Y-%m-%d %H:%M:%S", localtime(lastRefresh));
    snprintf(sql, sizeof(sql), "SELECT sender_id, recipient_id, content, is_encrypted, iv,timestamp, id FROM messages WHERE (recipient_id == '%s' OR recipient_id IS NULL OR sender_id = '%s') AND timestamp > '%s' ORDER BY timestamp;", uid, uid, lastRefreshStr);
    int rc = sqlite3_open("./chat.db", &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);

    rc = sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    printf("refresh string: %s\n", lastRefreshStr);

    return 0;
}

int insert_user(char **res, char *uid, char *password)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;

    const size_t result_size = 200;
    *res = calloc(result_size, sizeof(char));

    const char *sql = "INSERT INTO users VALUES (?, ?, 1);";
    int rc = sqlite3_open("./chat.db", &db);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, uid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, (const char *)password, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if (rc == SQLITE_DONE)
    {
        snprintf(*res, result_size, "registration succeeded");
    }
    else if (rc == SQLITE_CONSTRAINT)
    {
        snprintf(*res, result_size, "error: user %s already exists", uid);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 1;
    }
    else
    {
        snprintf(*res, result_size, "Failed to insert user: %s", sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return 0;
}

int get_user_list(sqlite3_stmt **stmt)
{
    sqlite3 *db;
    const char *sql = "SELECT user_id FROM users WHERE devices > 0;";
    int rc = sqlite3_open("./chat.db", &db);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }
sqlite3_busy_timeout(db, 5000);
    rc = sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    return 0;
}

int search_user(char **res, char *uid, char *password)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;

    const size_t result_size = 200;
    *res = calloc(result_size, sizeof(char));

    const char *check_user_sql = "SELECT COUNT(*) FROM users WHERE user_id = ? AND password = ?;";
    const char *update_devices_sql = "UPDATE users SET devices = devices + 1 WHERE user_id = ?;";

    int rc = sqlite3_open("./chat.db", &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }sqlite3_busy_timeout(db, 5000);
    rc = sqlite3_prepare_v2(db, check_user_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, uid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    printf("Value check: %d\n", sqlite3_column_int(stmt, 0));
    if (rc == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0)
    {
        sqlite3_finalize(stmt);

        rc = sqlite3_prepare_v2(db, update_devices_sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "Failed to prepare update statement: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return -1;
        }
        sqlite3_bind_text(stmt, 1, uid, -1, SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE)
        {
            snprintf(*res, result_size, "authentication succeeded");
        }
        else
        {
            snprintf(*res, result_size, "Error updating devices for user '%s': %s\n", uid, sqlite3_errmsg(db));
        }
    }
    else
    {
        snprintf(*res, result_size, "error: invalid credentials");

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        return 1;
    }
    printf(" testing testing\n");
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return 0;
}