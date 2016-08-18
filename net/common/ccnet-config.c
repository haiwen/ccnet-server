/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "ccnet-config.h"

static gboolean
get_value (sqlite3_stmt *stmt, void *data)
{
    char **p_value = data;

    *p_value = g_strdup((char *) sqlite3_column_text (stmt, 0));
    /* Only one result. */
    return FALSE;
}

static char *
config_get_string (sqlite3 *config_db, const char *key)
{
    char sql[256];
    char *value = NULL;

    snprintf (sql, sizeof(sql), 
              "SELECT value FROM Config WHERE key='%s';",
              key);
    if (sqlite_foreach_selected_row (config_db, sql,
                                     get_value, &value) < 0)
        return NULL;

    return value;
}

char *
ccnet_session_config_get_string (CcnetSession *session,
                                 const char *key)
{
    return (config_get_string (session->config_db, key));
}

int
ccnet_session_config_get_int (CcnetSession *session,
                              const char *key,
                              gboolean *exists)
{
    char *value;
    int ret;

    value = config_get_string (session->config_db, key);
    if (!value) {
        *exists = FALSE;
        return -1;
    }

    *exists = TRUE;
    ret = atoi (value);
    g_free (value);
    return ret;
}

int
ccnet_session_config_set_string (CcnetSession *session,
                                 const char *key,
                                 const char *value)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "REPLACE INTO Config VALUES ('%s', '%s');",
              key, value);
    if (sqlite_query_exec (session->config_db, sql) < 0)
        return -1;

    return 0;
}

int
ccnet_session_config_set_int (CcnetSession *session,
                              const char *key,
                              int value)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "REPLACE INTO Config VALUES ('%s', %d);",
              key, value);
    if (sqlite_query_exec (session->config_db, sql) < 0)
        return -1;

    return 0;
}

sqlite3 *
ccnet_session_config_open_db (const char *ccnet_dir)
{
    sqlite3 *db;
    char *db_path;

    db_path = g_build_filename (ccnet_dir, "config.db", NULL);
    if (sqlite_open_db (db_path, &db) < 0)
        return NULL;
    g_free (db_path);

    /*
     * Values are stored in text. You should convert it
     * back to integer if needed when you read it from
     * db.
     */
    char *sql = "CREATE TABLE IF NOT EXISTS Config ("
        "key TEXT PRIMARY KEY, "
        "value TEXT);";
    sqlite_query_exec (db, sql);

    return db;
}
