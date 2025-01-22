#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

// DO NOT RUN THIS FILE. THIS IS ONLY TO SAVE SOME SAMPLE QUERIES TEMPLATE

// Function to execute a simple SQL query (INSERT, UPDATE, DELETE)
void execute_sql(sqlite3 *db, const char *sql) {
    char *err_msg = NULL;
    
    // Print the query being executed
    printf("Executing SQL: %s\n", sql);
    
    // Execute the SQL query
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    
    // Check for errors
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);  // Free error message
    } else {
        printf("Query executed successfully.\n");
    }
}

// Callback function to process the result of SELECT query
int callback(void *data, int argc, char **argv, char **col_names) {
    for (int i = 0; i < argc; i++) {
        printf("%s = %s\n", col_names[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

// Function to execute a SELECT query and print the results
void execute_select(sqlite3 *db, const char *sql) {
    char *err_msg = NULL;
    
    // Print the SELECT query
    printf("Executing SQL: %s\n", sql);
    
    // Execute the SELECT query with the callback function
    int rc = sqlite3_exec(db, sql, callback, 0, &err_msg);
    
    // Check for errors
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);  // Free error message
    } else {
        printf("SELECT query executed successfully.\n");
    }
}

int main() {
    sqlite3 *db;
    int rc;

    // Open database (will create it if it doesn't exist)
    rc = sqlite3_open("./chat.db", &db);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return EXIT_FAILURE;
    }
    
    printf("Connected to database successfully.\n");

    // Example INSERT query to add a user
    const char *insert_sql = "INSERT INTO users (user_id, password) VALUES ('user1', 'hashed_password');";
    execute_sql(db, insert_sql);

    // Example UPDATE query to change a user's password
    const char *update_sql = "UPDATE users SET password = 'new_hashed_password' WHERE user_id = 'user1';";
    execute_sql(db, update_sql);

    // Example DELETE query to remove a user
    const char *delete_sql = "DELETE FROM users WHERE user_id = 'user1';";
    execute_sql(db, delete_sql);

    // Example SELECT query to retrieve all users
    const char *select_sql = "SELECT * FROM users;";
    execute_select(db, select_sql);

    // Close the database
    sqlite3_close(db);
    printf("Database connection closed.\n");

    return EXIT_SUCCESS;
}
