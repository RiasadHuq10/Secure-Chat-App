#ifndef DATABASE_H_
#define DATABASE_H_

#include <sqlite3.h>
#include <time.h>

void create_tables(sqlite3 *db);
int setup_db();
int get_messages(sqlite3_stmt **stmt, char *uid, time_t *lastRefresh);
int insert_user(char **res, char *uid, char *password);
int get_user_list(sqlite3_stmt **stmt);
int search_user(char **res, char *uid, char *password);
int insert_public_message(const char *sender_id, const char *content, const char *timestamp);
int insert_private_message(const char *sender_id, const char *recipient_id, const char *content, const char *iv, const char *timestamp, int content_len);
int user_exists(const char *recipient_id);

#endif