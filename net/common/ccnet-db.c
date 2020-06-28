
#include "common.h"

#include "log.h"

#include "ccnet-db.h"

#include <stdarg.h>
#ifdef HAVE_MYSQL
#include <mysql.h>
#endif
#ifdef HAVE_POSTGRESQL
#include <libpq-fe.h>
#endif
#include <sqlite3.h>
#include <pthread.h>

struct CcnetDB {
    int type;
};

typedef struct DBConnection {
    /* Empty */
} DBConnection;

struct CcnetDBRow {
    /* Empty */
};

struct CcnetDBTrans {
    DBConnection *conn;
};

typedef struct DBOperations {
    DBConnection* (*get_connection)(CcnetDB *db);
    void (*release_connection)(DBConnection *conn);
    int (*execute_sql_no_stmt)(DBConnection *conn, const char *sql);
    int (*execute_sql)(DBConnection *conn, const char *sql,
                       int n, va_list args);
    int (*query_foreach_row)(DBConnection *conn,
                             const char *sql, CcnetDBRowFunc callback, void *data,
                             int n, va_list args);
    int (*row_get_column_count)(CcnetDBRow *row);
    const char* (*row_get_column_string)(CcnetDBRow *row, int idx);
    int (*row_get_column_int)(CcnetDBRow *row, int idx);
    gint64 (*row_get_column_int64)(CcnetDBRow *row, int idx);
} DBOperations;

static DBOperations db_ops;

#ifdef HAVE_MYSQL

/* MySQL Ops */
static CcnetDB *
mysql_db_new (const char *host,
              int port,
              const char *user,
              const char *password,
              const char *db_name,
              const char *unix_socket,
              gboolean use_ssl,
              const char *charset);
static DBConnection *
mysql_db_get_connection (CcnetDB *db);
static void
mysql_db_release_connection (DBConnection *vconn);
static int
mysql_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql);
static int
mysql_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args);
static int
mysql_db_query_foreach_row (DBConnection *vconn, const char *sql,
                            CcnetDBRowFunc callback, void *data,
                            int n, va_list args);
static int
mysql_db_row_get_column_count (CcnetDBRow *row);
static const char *
mysql_db_row_get_column_string (CcnetDBRow *row, int idx);
static int
mysql_db_row_get_column_int (CcnetDBRow *row, int idx);
static gint64
mysql_db_row_get_column_int64 (CcnetDBRow *row, int idx);

CcnetDB *
ccnet_db_new_mysql (const char *host,
                   int port,
                   const char *user, 
                   const char *passwd,
                   const char *db_name,
                   const char *unix_socket,
                   gboolean use_ssl,
                   const char *charset,
                   int max_connections)
{
    CcnetDB *db;

    db = mysql_db_new (host, port, user, passwd, db_name, unix_socket, use_ssl, charset);
    if (!db)
        return NULL;
    db->type = CCNET_DB_TYPE_MYSQL;

    db_ops.get_connection = mysql_db_get_connection;
    db_ops.release_connection = mysql_db_release_connection;
    db_ops.execute_sql_no_stmt = mysql_db_execute_sql_no_stmt;
    db_ops.execute_sql = mysql_db_execute_sql;
    db_ops.query_foreach_row = mysql_db_query_foreach_row;
    db_ops.row_get_column_count = mysql_db_row_get_column_count;
    db_ops.row_get_column_string = mysql_db_row_get_column_string;
    db_ops.row_get_column_int = mysql_db_row_get_column_int;
    db_ops.row_get_column_int64 = mysql_db_row_get_column_int64;

    return db;
}

#endif

#ifdef HAVE_POSTGRESQL

/* PostgreSQL Ops */
CcnetDB *
pgsql_db_new (const char *host,
                    unsigned int port,
                    const char *user,
                    const char *passwd,
                    const char *db_name,
                    const char *unix_socket);
static DBConnection *
pgsql_db_get_connection (CcnetDB *db);
static void
pgsql_db_release_connection (DBConnection *vconn);
static int
pgsql_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql);
static int
pgsql_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args);
static int
pgsql_db_query_foreach_row (DBConnection *vconn,
                            const char *sql, CcnetDBRowFunc callback,
                            void *data, int n, va_list args);
static int
pgsql_db_row_get_column_count (CcnetDBRow *row);
static const char *
pgsql_db_row_get_column_string (CcnetDBRow *row, int idx);
static int
pgsql_db_row_get_column_int (CcnetDBRow *row, int idx);
static gint64
pgsql_db_row_get_column_int64 (CcnetDBRow *row, int idx);

CcnetDB *
ccnet_db_new_pgsql (const char *host,
                    unsigned int port,
                    const char *user,
                    const char *passwd,
                    const char *db_name,
                    const char *unix_socket,
                    int max_connections)
{
    CcnetDB *db;

    db = pgsql_db_new (host, port, user, passwd, db_name, unix_socket);
    if (!db)
        return NULL;
    db->type = CCNET_DB_TYPE_PGSQL;

    db_ops.get_connection = pgsql_db_get_connection;
    db_ops.release_connection = pgsql_db_release_connection;
    db_ops.execute_sql_no_stmt = pgsql_db_execute_sql_no_stmt;
    db_ops.execute_sql = pgsql_db_execute_sql;
    db_ops.query_foreach_row = pgsql_db_query_foreach_row;
    db_ops.row_get_column_count = pgsql_db_row_get_column_count;
    db_ops.row_get_column_string = pgsql_db_row_get_column_string;
    db_ops.row_get_column_int = pgsql_db_row_get_column_int;
    db_ops.row_get_column_int64 = pgsql_db_row_get_column_int64;

    return db;
}

#endif

/* SQLite Ops */
static CcnetDB *
sqlite_db_new (const char *db_path);
static DBConnection *
sqlite_db_get_connection (CcnetDB *db);
static void
sqlite_db_release_connection (DBConnection *vconn);
static int
sqlite_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql);
static int
sqlite_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args);
static int
sqlite_db_query_foreach_row (DBConnection *vconn, const char *sql,
                             CcnetDBRowFunc callback, void *data,
                             int n, va_list args);
static int
sqlite_db_row_get_column_count (CcnetDBRow *row);
static const char *
sqlite_db_row_get_column_string (CcnetDBRow *row, int idx);
static int
sqlite_db_row_get_column_int (CcnetDBRow *row, int idx);
static gint64
sqlite_db_row_get_column_int64 (CcnetDBRow *row, int idx);

CcnetDB *
ccnet_db_new_sqlite (const char *db_path)
{
    CcnetDB *db;

    db = sqlite_db_new (db_path);
    if (!db)
        return NULL;
    db->type = CCNET_DB_TYPE_SQLITE;

    db_ops.get_connection = sqlite_db_get_connection;
    db_ops.release_connection = sqlite_db_release_connection;
    db_ops.execute_sql_no_stmt = sqlite_db_execute_sql_no_stmt;
    db_ops.execute_sql = sqlite_db_execute_sql;
    db_ops.query_foreach_row = sqlite_db_query_foreach_row;
    db_ops.row_get_column_count = sqlite_db_row_get_column_count;
    db_ops.row_get_column_string = sqlite_db_row_get_column_string;
    db_ops.row_get_column_int = sqlite_db_row_get_column_int;
    db_ops.row_get_column_int64 = sqlite_db_row_get_column_int64;

    return db;
}

int
ccnet_db_type (CcnetDB *db)
{
    return db->type;
}

int
ccnet_db_query (CcnetDB *db, const char *sql)
{
    DBConnection *conn = db_ops.get_connection (db);
    if (!conn)
        return -1;

    int ret;
    ret = db_ops.execute_sql_no_stmt (conn, sql);

    db_ops.release_connection (conn);
    return ret;
}

gboolean
ccnet_db_check_for_existence (CcnetDB *db, const char *sql, gboolean *db_err)
{
    return ccnet_db_statement_exists (db, sql, db_err, 0);
}

int
ccnet_db_foreach_selected_row (CcnetDB *db, const char *sql, 
                              CcnetDBRowFunc callback, void *data)
{
    return ccnet_db_statement_foreach_row (db, sql, callback, data, 0);
}

const char *
ccnet_db_row_get_column_text (CcnetDBRow *row, guint32 idx)
{
    g_return_val_if_fail (idx < db_ops.row_get_column_count(row), NULL);

    return db_ops.row_get_column_string (row, idx);
}

int
ccnet_db_row_get_column_int (CcnetDBRow *row, guint32 idx)
{
    g_return_val_if_fail (idx < db_ops.row_get_column_count(row), -1);

    return db_ops.row_get_column_int (row, idx);
}

gint64
ccnet_db_row_get_column_int64 (CcnetDBRow *row, guint32 idx)
{
    g_return_val_if_fail (idx < db_ops.row_get_column_count(row), -1);

    return db_ops.row_get_column_int64 (row, idx);
}

int
ccnet_db_get_int (CcnetDB *db, const char *sql)
{
    return ccnet_db_statement_get_int (db, sql, 0);
}

gint64
ccnet_db_get_int64 (CcnetDB *db, const char *sql)
{
    return ccnet_db_statement_get_int64 (db, sql, 0);
}

char *
ccnet_db_get_string (CcnetDB *db, const char *sql)
{
    return ccnet_db_statement_get_string (db, sql, 0);
}

int
ccnet_db_statement_query (CcnetDB *db, const char *sql, int n, ...)
{
    int ret;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection (db);
    if (!conn)
        return -1;

    va_list args;
    va_start (args, n);
    ret = db_ops.execute_sql (conn, sql, n, args);
    va_end (args);

    db_ops.release_connection (conn);

    return ret;
}

gboolean
ccnet_db_statement_exists (CcnetDB *db, const char *sql, gboolean *db_err, int n, ...)
{
    int n_rows;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection(db);
    if (!conn)
        return FALSE;

    va_list args;
    va_start (args, n);
    n_rows = db_ops.query_foreach_row (conn, sql, NULL, NULL, n, args);
    va_end (args);

    db_ops.release_connection(conn);

    if (n_rows < 0) {
        *db_err = TRUE;
        return FALSE;
    } else {
        *db_err = FALSE;
        return (n_rows != 0);
    }
}

int
ccnet_db_statement_foreach_row (CcnetDB *db, const char *sql,
                               CcnetDBRowFunc callback, void *data,
                               int n, ...)
{
    int ret;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection (db);
    if (!conn)
        return -1;

    va_list args;
    va_start (args, n);
    ret = db_ops.query_foreach_row (conn, sql, callback, data, n, args);
    va_end (args);

    db_ops.release_connection (conn);

    return ret;
}

static gboolean
get_int_cb (CcnetDBRow *row, void *data)
{
    int *pret = (int*)data;

    *pret = ccnet_db_row_get_column_int (row, 0);

    return FALSE;
}

int
ccnet_db_statement_get_int (CcnetDB *db, const char *sql, int n, ...)
{
    int ret = -1;
    int rc;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection (db);
    if (!conn)
        return -1;

    va_list args;
    va_start (args, n);
    rc = db_ops.query_foreach_row (conn, sql, get_int_cb, &ret, n, args);
    va_end (args);

    db_ops.release_connection (conn);

    if (rc < 0)
        return -1;

    return ret;
}

static gboolean
get_int64_cb (CcnetDBRow *row, void *data)
{
    gint64 *pret = (gint64*)data;

    *pret = ccnet_db_row_get_column_int64 (row, 0);

    return FALSE;
}

gint64
ccnet_db_statement_get_int64 (CcnetDB *db, const char *sql, int n, ...)
{
    gint64 ret = -1;
    int rc;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection (db);
    if (!conn)
        return -1;

    va_list args;
    va_start (args, n);
    rc = db_ops.query_foreach_row (conn, sql, get_int64_cb, &ret, n, args);
    va_end(args);

    db_ops.release_connection (conn);

    if (rc < 0)
        return -1;

    return ret;
}

static gboolean
get_string_cb (CcnetDBRow *row, void *data)
{
    char **pret = (char**)data;

    *pret = g_strdup(ccnet_db_row_get_column_text (row, 0));

    return FALSE;
}

char *
ccnet_db_statement_get_string (CcnetDB *db, const char *sql, int n, ...)
{
    char *ret = NULL;
    int rc;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection (db);
    if (!conn)
        return NULL;

    va_list args;
    va_start (args, n);
    rc = db_ops.query_foreach_row (conn, sql, get_string_cb, &ret, n, args);
    va_end(args);

    db_ops.release_connection (conn);

    if (rc < 0)
        return NULL;

    return ret;
}

/* Transaction */

CcnetDBTrans *
ccnet_db_begin_transaction (CcnetDB *db)
{
    CcnetDBTrans *trans = NULL;
    DBConnection *conn = db_ops.get_connection(db);
    if (!conn) {
        return trans;
    }

    if (db_ops.execute_sql_no_stmt (conn, "BEGIN") < 0) {
        db_ops.release_connection (conn);
        return trans;
    }

    trans = g_new0 (CcnetDBTrans, 1);
    trans->conn = conn;

    return trans;
}

void
ccnet_db_trans_close (CcnetDBTrans *trans)
{
    db_ops.release_connection (trans->conn);
    g_free (trans);
}

int
ccnet_db_commit (CcnetDBTrans *trans)
{
    DBConnection *conn = trans->conn;

    if (db_ops.execute_sql_no_stmt (conn, "COMMIT") < 0) {
        return -1;
    }

    return 0;
}

int
ccnet_db_rollback (CcnetDBTrans *trans)
{
    DBConnection *conn = trans->conn;

    if (db_ops.execute_sql_no_stmt (conn, "ROLLBACK") < 0) {
        return -1;
    }

    return 0;
}

int
ccnet_db_trans_query (CcnetDBTrans *trans, const char *sql, int n, ...)
{
    int ret;

    va_list args;
    va_start (args, n);
    ret = db_ops.execute_sql (trans->conn, sql, n, args);
    va_end (args);

    return ret;
}

gboolean
ccnet_db_trans_check_for_existence (CcnetDBTrans *trans,
                                   const char *sql,
                                   gboolean *db_err,
                                   int n, ...)
{
    int n_rows;

    va_list args;
    va_start (args, n);
    n_rows = db_ops.query_foreach_row (trans->conn, sql, NULL, NULL, n, args);
    va_end (args);

    if (n_rows < 0) {
        *db_err = TRUE;
        return FALSE;
    } else {
        *db_err = FALSE;
        return (n_rows != 0);
    }
}

int
ccnet_db_trans_foreach_selected_row (CcnetDBTrans *trans, const char *sql, 
                                    CcnetDBRowFunc callback, void *data,
                                    int n, ...)
{
    int ret;

    va_list args;
    va_start (args, n);
    ret = db_ops.query_foreach_row (trans->conn, sql, callback, data, n, args);
    va_end (args);

    return ret;
}

#ifdef HAVE_MYSQL

/* MySQL DB */

typedef struct MySQLDB {
    struct CcnetDB parent;
    char *host;
    char *user;
    char *password;
    unsigned int port;
    char *db_name;
    char *unix_socket;
    gboolean use_ssl;
    char *charset;
} MySQLDB;

typedef struct MySQLDBConnection {
    struct DBConnection parent;
    MYSQL *db_conn;
} MySQLDBConnection;

static CcnetDB *
mysql_db_new (const char *host,
              int port,
              const char *user,
              const char *password,
              const char *db_name,
              const char *unix_socket,
              gboolean use_ssl,
              const char *charset)
{
    MySQLDB *db = g_new0 (MySQLDB, 1);

    if (host) {db->host = g_strdup (host);} else {db->host = NULL;}
    db->user = g_strdup (user);
    db->password = g_strdup (password);
    db->port = port;
    db->db_name = g_strdup(db_name);
    if (unix_socket) {db->unix_socket = g_strdup(unix_socket);} else {db->unix_socket = NULL;}
    if (use_ssl) {db->use_ssl = use_ssl;} else {db->use_ssl = NULL;}
    db->charset = g_strdup(charset);

    mysql_library_init (0, NULL, NULL);

    return (CcnetDB *)db;
}

static DBConnection *
mysql_db_get_connection (CcnetDB *vdb)
{
    MySQLDB *db = (MySQLDB *)vdb;
    my_bool yes = 1;
    int conn_timeout = 1;
    MYSQL *db_conn;
    MySQLDBConnection *conn = NULL;

    db_conn = mysql_init (NULL);
    if (!db_conn) {
        ccnet_warning ("Failed to init mysql connection object.\n");
        return NULL;
    }

    if (db->use_ssl)
        mysql_ssl_set(db_conn, 0,0,0,0,0);

    if (db->charset)
        mysql_options(db_conn, MYSQL_SET_CHARSET_NAME, db->charset);

    mysql_options(db_conn, MYSQL_OPT_CONNECT_TIMEOUT, (const char*)&conn_timeout);
    mysql_options(db_conn, MYSQL_OPT_RECONNECT, (const char*)&yes);

    if (!mysql_real_connect(db_conn, db->host, db->user, db->password,
                            db->db_name, db->port,
                            db->unix_socket, CLIENT_MULTI_STATEMENTS)) {
        ccnet_warning ("Failed to connect to MySQL: %s\n", mysql_error(db_conn));
        mysql_close (db_conn);
        return NULL;
    }

    conn = g_new0 (MySQLDBConnection, 1);
    conn->db_conn = db_conn;

    return (DBConnection *)conn;
}

static void
mysql_db_release_connection (DBConnection *vconn)
{
    if (!vconn)
        return;

    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    mysql_close (conn->db_conn);

    g_free (conn);
}

static int
mysql_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    if (mysql_query (conn->db_conn, sql) != 0) {
        ccnet_warning ("Failed to execute sql %s: %s\n", sql, mysql_error(conn->db_conn));
        return -1;
    }

    return 0;
}

static MYSQL_STMT *
_prepare_stmt_mysql (MYSQL *db, const char *sql)
{
    MYSQL_STMT *stmt;

    stmt = mysql_stmt_init (db);
    if (!stmt) {
        ccnet_warning ("mysql_stmt_init failed.\n");
        return NULL;
    }

    if (mysql_stmt_prepare (stmt, sql, strlen(sql)) != 0) {
        ccnet_warning ("Failed to prepare sql %s: %s\n", sql, mysql_stmt_error(stmt));
        mysql_stmt_close (stmt);
        return NULL;
    }

    return stmt;
}

static int
_bind_params_mysql (MYSQL_STMT *stmt, MYSQL_BIND *params, int n, va_list args)
{
    int i;
    const char *type;

    for (i = 0; i < n; ++i) {
        type = va_arg (args, const char *);
        if (strcmp(type, "int") == 0) {
            int x = va_arg (args, int);
            int *pval = g_new (int, 1);
            *pval = x;
            params[i].buffer_type = MYSQL_TYPE_LONG;
            params[i].buffer = pval;
            params[i].is_null = 0;
        } else if (strcmp (type, "int64") == 0) {
            gint64 x = va_arg (args, gint64);
            gint64 *pval = g_new (gint64, 1);
            *pval = x;
            params[i].buffer_type = MYSQL_TYPE_LONGLONG;
            params[i].buffer = pval;
            params[i].is_null = 0;
        } else if (strcmp (type, "string") == 0) {
            const char *s = va_arg (args, const char *);
            static my_bool yes = TRUE;
            params[i].buffer_type = MYSQL_TYPE_STRING;
            params[i].buffer = g_strdup(s);
            unsigned long *plen = g_new (unsigned long, 1);
            params[i].length = plen;
            if (!s) {
                *plen = 0;
                params[i].buffer_length = 0;
                params[i].is_null = &yes;
            } else {
                *plen = strlen(s);
                params[i].buffer_length = *plen + 1;
                params[i].is_null = 0;
            }
        } else {
            ccnet_warning ("BUG: invalid prep stmt parameter type %s.\n", type);
            g_return_val_if_reached (-1);
        }
    }

    if (mysql_stmt_bind_param (stmt, params) != 0) {
        return -1;
    }

    return 0;
}

static int
mysql_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;
    MYSQL *db = conn->db_conn;
    MYSQL_STMT *stmt = NULL;
    MYSQL_BIND *params = NULL;
    int ret = 0;

    stmt = _prepare_stmt_mysql (db, sql);
    if (!stmt) {
        return -1;
    }

    if (n > 0) {
        params = g_new0 (MYSQL_BIND, n);
        if (_bind_params_mysql (stmt, params, n, args) < 0) {
            ccnet_warning ("Failed to bind parameters for %s: %s.\n",
                          sql, mysql_stmt_error(stmt));
            ret = -1;
            goto out;
        }
    }

    if (mysql_stmt_execute (stmt) != 0) {
        ccnet_warning ("Failed to execute sql %s: %s\n", sql, mysql_stmt_error(stmt));
        ret = -1;
        goto out;
    }

out:
    if (stmt)
        mysql_stmt_close (stmt);
    if (params) {
        int i;
        for (i = 0; i < n; ++i) {
            g_free (params[i].buffer);
            g_free (params[i].length);
        }
        g_free (params);
    }
    return ret;
}

typedef struct MySQLDBRow {
    CcnetDBRow parent;
    int column_count;
    MYSQL_STMT *stmt;
    MYSQL_BIND *results;
    /* Used when returned columns are truncated. */
    MYSQL_BIND *new_binds;
} MySQLDBRow;

#define DEFAULT_MYSQL_COLUMN_SIZE 1024

static int
mysql_db_query_foreach_row (DBConnection *vconn, const char *sql,
                            CcnetDBRowFunc callback, void *data,
                            int n, va_list args)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;
    MYSQL *db = conn->db_conn;
    MYSQL_STMT *stmt = NULL;
    MYSQL_BIND *params = NULL;
    MySQLDBRow row;
    int nrows = 0;
    int i;

    memset (&row, 0, sizeof(row));

    stmt = _prepare_stmt_mysql (db, sql);
    if (!stmt) {
        return -1;
    }

    if (n > 0) {
        params = g_new0 (MYSQL_BIND, n);
        if (_bind_params_mysql (stmt, params, n, args) < 0) {
            nrows = -1;
            goto out;
        }
    }

    if (mysql_stmt_execute (stmt) != 0) {
        ccnet_warning ("Failed to execute sql %s: %s\n", sql, mysql_stmt_error(stmt));
        nrows = -1;
        goto out;
    }

    row.column_count = mysql_stmt_field_count (stmt);
    row.stmt = stmt;
    row.results = g_new0 (MYSQL_BIND, row.column_count);
    for (i = 0; i < row.column_count; ++i) {
        row.results[i].buffer = g_malloc (DEFAULT_MYSQL_COLUMN_SIZE + 1);
        /* Ask MySQL to convert fields to string, to avoid the trouble of
         * checking field types.
         */
        row.results[i].buffer_type = MYSQL_TYPE_STRING;
        row.results[i].buffer_length = DEFAULT_MYSQL_COLUMN_SIZE;
        row.results[i].length = g_new0 (unsigned long, 1);
        row.results[i].is_null = g_new0 (my_bool, 1);
    }
    row.new_binds = g_new0 (MYSQL_BIND, row.column_count);

    if (mysql_stmt_bind_result (stmt, row.results) != 0) {
        ccnet_warning ("Failed to bind result for sql %s: %s\n", sql, mysql_stmt_error(stmt));
        nrows = -1;
        goto out;
    }

    int rc;
    gboolean next_row = TRUE;
    while (1) {
        rc = mysql_stmt_fetch (stmt);
        if (rc == 1) {
            ccnet_warning ("Failed to fetch result for sql %s: %s\n",
                          sql, mysql_stmt_error(stmt));
            nrows = -1;
            goto out;
        }
        if (rc == MYSQL_NO_DATA)
            break;

        /* rc == 0 or rc == MYSQL_DATA_TRUNCATED */

        ++nrows;
        if (callback)
            next_row = callback ((CcnetDBRow *)&row, data);

        for (i = 0; i < row.column_count; ++i) {
            g_free (row.new_binds[i].buffer);
            g_free (row.new_binds[i].length);
            g_free (row.new_binds[i].is_null);
            memset (&row.new_binds[i], 0, sizeof(MYSQL_BIND));
        }

        if (!next_row)
            break;
    }

out:
    if (stmt) {
        mysql_stmt_free_result (stmt);
        mysql_stmt_close (stmt);
    }
    if (params) {
        for (i = 0; i < n; ++i) {
            g_free (params[i].buffer);
            g_free (params[i].length);
        }
        g_free (params);
    }
    if (row.results) {
        for (i = 0; i < row.column_count; ++i) {
            g_free (row.results[i].buffer);
            g_free (row.results[i].length);
            g_free (row.results[i].is_null);
        }
        g_free (row.results);
    }
    if (row.new_binds) {
        for (i = 0; i < row.column_count; ++i) {
            g_free (row.new_binds[i].buffer);
            g_free (row.new_binds[i].length);
            g_free (row.new_binds[i].is_null);
        }
        g_free (row.new_binds);
    }
    return nrows;
}

static int
mysql_db_row_get_column_count (CcnetDBRow *vrow)
{
    MySQLDBRow *row = (MySQLDBRow *)vrow;
    return row->column_count;
}

static const char *
mysql_db_row_get_column_string (CcnetDBRow *vrow, int i)
{
    MySQLDBRow *row = (MySQLDBRow *)vrow;

    if (*(row->results[i].is_null)) {
        return NULL;
    }

    char *ret = NULL;
    unsigned long real_length = *(row->results[i].length);
    /* If column size is larger then allocated buffer size, re-allocate a new buffer
     * and fetch the column directly.
     */
    if (real_length > row->results[i].buffer_length) {
        row->new_binds[i].buffer = g_malloc (real_length + 1);
        row->new_binds[i].buffer_type = MYSQL_TYPE_STRING;
        row->new_binds[i].buffer_length = real_length;
        row->new_binds[i].length = g_new0 (unsigned long, 1);
        row->new_binds[i].is_null = g_new0 (my_bool, 1);
        if (mysql_stmt_fetch_column (row->stmt, &row->new_binds[i], i, 0) != 0) {
            ccnet_warning ("Faield to fetch column: %s\n", mysql_stmt_error(row->stmt));
            return NULL;
        }

        ret = row->new_binds[i].buffer;
    } else {
        ret = row->results[i].buffer;
    }
    ret[real_length] = 0;

    return ret;
}

static int
mysql_db_row_get_column_int (CcnetDBRow *vrow, int idx)
{
    const char *str;
    char *e;
    int ret;

    str = mysql_db_row_get_column_string (vrow, idx);
    if (!str) {
        return 0;
    }

    errno = 0;
    ret = strtol (str, &e, 10);
    if (errno || (e == str)) {
        ccnet_warning ("Number conversion failed.\n");
        return -1;
    }

    return ret;
}

static gint64
mysql_db_row_get_column_int64 (CcnetDBRow *vrow, int idx)
{
    const char *str;
    char *e;
    gint64 ret;

    str = mysql_db_row_get_column_string (vrow, idx);
    if (!str) {
        return 0;
    }

    errno = 0;
    ret = strtoll (str, &e, 10);
    if (errno || (e == str)) {
        ccnet_warning ("Number conversion failed.\n");
        return -1;
    }

    return ret;
}

#endif  /* HAVE_MYSQL */

#ifdef HAVE_POSTGRESQL

typedef struct PostgreSQLDB {
    struct CcnetDB parent;
    char *host;
    char *user;
    char *password;
    unsigned int port;
    char *db_name;
    char *unix_socket;
} PostgreSQLDB;

typedef struct PGDBConnection {
    struct DBConnection parent;
    PGconn *db_conn;
} PGDBConnection;

CcnetDB *
pgsql_db_new (const char *host,
                    unsigned int port,
                    const char *user,
                    const char *password,
                    const char *db_name,
                    const char *unix_socket)
{
    PostgreSQLDB *db = g_new0 (PostgreSQLDB, 1);

    if (host) {db->host = g_strdup (host);} else {db->host = NULL;}
    db->user = g_strdup (user);
    db->password = g_strdup (password);
    db->port = port;
    db->db_name = g_strdup(db_name);
    if (unix_socket) {db->unix_socket = g_strdup(unix_socket);} else {db->unix_socket = NULL;}

    return (CcnetDB *)db;
}

static char *
_escape_string_pgsql_connect (const char *str)
{
    GString *buf = g_string_new (NULL);
    const char *p;

    for (p = str; *p != '\0'; ++p) {
        if (*p == '\'' || *p == '\\') {
            g_string_append_c (buf, '\\');
            g_string_append_c (buf, *p);
        } else {
            g_string_append_c (buf, *p);
        }
    }

    return g_string_free (buf, FALSE);
}

static DBConnection *
pgsql_db_get_connection (CcnetDB *vdb)
{
    GString *conn_string = g_string_new("");
    char *esc_password = NULL;
    PostgreSQLDB *db = (PostgreSQLDB *)vdb;
    PGconn *db_conn;
    PGDBConnection *conn;

    g_string_append_printf (conn_string, "user='%s' ", db->user);

    esc_password = _escape_string_pgsql_connect (db->password);
    g_string_append_printf (conn_string, "password='%s' ", esc_password);
    
    if (db->unix_socket) {
        g_string_append_printf (conn_string, "host='%s' ", db->unix_socket);
    } else {
        g_string_append_printf (conn_string, "host='%s' ", db->host);
    }

    if (db->port > 0) {
        g_string_append_printf (conn_string, "port=%u ", db->port);
    }

    g_string_append_printf (conn_string, "dbname='%s' ", db->db_name);
 
    db_conn = PQconnectdb (conn_string->str);
    if (PQstatus (db_conn) != CONNECTION_OK) {
        ccnet_warning ("Failed to connect to PostgreSQL: %s\n", PQerrorMessage(db_conn));
        PQfinish (db_conn);
        exit -1;
    }


    g_free (esc_password);
    g_string_free (conn_string, TRUE);
    
    conn = g_new0 (PGDBConnection, 1);
    conn->db_conn = db_conn;

    return (DBConnection *)conn;
}

static void
pgsql_db_release_connection (DBConnection *vconn)
{
    if (!vconn)
        return;

    PGDBConnection *conn = (PGDBConnection *)vconn;

    PQfinish (conn->db_conn);

    g_free (conn);
}

static GString *
_convert_sql_params_pgsql(const char *sql)
{
    GString *ret = g_string_new("");
    char buf;
    
    int i, param_count = 0;    
    for(i = 0; sql[i] != '\0' || i < strlen(sql); ++i)
    {
        buf = sql[i];
        if(sql[i] == '?'){
            ++param_count;
            g_string_append_printf (ret, "%s%d", "$", param_count);
        } else            
            g_string_append (ret, &buf);
    }
    
    return ret;
}

static const GString *
_get_stmtname_from_time_pgsql()
{
    GString *stmt_name = g_string_new("ccnet.");
    char cur_time[17];    
    struct tm time;    
    struct timespec ts;
    
    clock_gettime(CLOCK_REALTIME, &ts);

    tzset();
    localtime_r(&(ts.tv_sec), &time);

    strftime(cur_time, sizeof(cur_time), "%H%M%S", &time);

    g_string_append_printf (stmt_name, ".%s", cur_time);
    
    g_string_append_printf (stmt_name, ".%09ld", ts.tv_nsec);
    
    return stmt_name;
}

/*
static const GString *
_get_stmtname_from_sql_pgsql(const char *sql, int n, va_list args)
{
    GString *stmt_name = g_string_new("");    
    char *buf, *cut_sql;
    int i;
    char *const q_list[] = {"SELECT", "INSERT", "UPDATE", "DELETE"};
    
    for (int idx = 0; idx < 4; ++idx)
    {
        if (g_str_has_prefix(sql, q_list[idx]) == 1){
            g_string_append (stmt_name, q_list[idx]);            
            cut_sql = g_strstr_len(sql, -1, q_list[idx]);
            
            buf = g_strstr_len(sql, -1, "FROM");
            if(!buf) buf = g_strstr_len(sql, -1, "INTO");
            if (buf) cut_sql = buf;
            
            int t=0;
            for (i=0; cut_sql[i] != '\0' || i < strlen(cut_sql); ++i)
            {
                if (cut_sql[i] == ' ' && cut_sql[i+1] != ' ')
                    t = i+1;
                    
                if (t > 0 && cut_sql[i] != ' ' && cut_sql[i+1] == ' '){
                    g_string_append (stmt_name, ".");
                    buf = g_strndup(cut_sql + t, (i - t) +1);
                    g_string_append(stmt_name, buf);
                    g_free(buf);
                    break;
                }
            } 
        }

    }
    
    if (strlen(stmt_name->str) == 0){
        g_string_free (stmt_name, TRUE);
        stmt_name = _get_stmtname_from_time_pgsql();
    }
    
    //Here error
    if (n > 0){
       for (i = 0; i < n; ++i) {
           g_string_append (stmt_name, ".");
           buf = va_arg (args, char *);
           g_string_append(stmt_name, buf);
       }
 
    }
    ccnet_warning("_get_stmtname_from_sql_pgsql: %s\n", stmt_name->str);
    return stmt_name;
}
*/

static PGresult *
_execute_sql_pgsql (DBConnection *vconn, const char *sql, int n, va_list args)
{    
    PGDBConnection *conn = (PGDBConnection *)vconn;
    PGconn *db = conn->db_conn;
    PGresult *result = NULL;

    GString *stmt_name;
    GString *sql_convert;
    int i;
    char *type;

    /* https://www.postgresql.org/docs/11/catalog-pg-type.html */
    /* sudo -u postgres -s psql -c "select oid, typname, typlen, typcategory from pg_type;" */
    Oid v_types[n];
    
    char *v_values[n];
    int v_lengths[n];    
    int v_formats[n]; //text:0 , binary:1
    int resultFormat = 0;
    
    if (n > 0)
    {
        stmt_name = _get_stmtname_from_time_pgsql();
        sql_convert = _convert_sql_params_pgsql(sql);
    
        for (i = 0; i < n; ++i) {
            type = va_arg (args, char *);
            if (strcmp(type, "int") == 0) {            
                int x = va_arg (args, int);
                v_values[i] = g_strdup_printf("%d", x);
                v_types[i] = 21;
                v_lengths[i] = sizeof(x);
                v_formats[i] = 0;
            } else if (strcmp (type, "int64") == 0) {
                gint64 x = va_arg (args, gint64);            
                v_values[i] = g_strdup_printf("%ld", x);
                v_types[i] = 20;
                v_lengths[i] = sizeof(x);
                v_formats[i] = 0;
            } else if (strcmp (type, "string") == 0) {
                char *s = va_arg (args, char *);
                v_values[i] = g_strdup(s);
                v_types[i] = 25;
                v_lengths[i] = sizeof(*s);
                v_formats[i] = 0;
            } else {
                ccnet_warning ("BUG: invalid prep stmt parameter type %s.\n", type);
                goto out;
            }
        }
        /*
        for (i = 0; i < 2; i++){            
            PQclear(result);
            result = PQexecPrepared(db, stmt_name->str, n, v_values, v_lengths, v_formats, resultFormat);
            //ccnet_warning ("pgsql_db_execute_sql PQexecPrepared result: %s\n", PQresStatus(PQresultStatus(result)));
        
            if (PQresultStatus(result) != PGRES_FATAL_ERROR){
                break;                
            } else {
                result = PQprepare(db, stmt_name->str, sql_convert->str, n, v_types);
                //ccnet_warning ("pgsql_db_execute_sql exec PQprepare \n");
                
                if (PQresultStatus(result) != PGRES_COMMAND_OK) {
                    ccnet_warning ("Failed to prepare sql: %s: %s\n", sql_convert->str, PQresultErrorMessage(result));
                    PQclear(result);
                    goto out;
                }
            }
        }
        */        
        result = PQprepare(db, stmt_name->str, sql_convert->str, n, v_types);
        
        if (PQresultStatus(result) != PGRES_COMMAND_OK) {
            ccnet_warning ("Failed to prepare sql: %s: %s\n", sql_convert->str, PQresultErrorMessage(result));
            PQclear(result);
            goto out;
        }else {
            PQclear(result);
            result = PQexecPrepared(db, stmt_name->str, n, v_values, v_lengths, v_formats, resultFormat);
        }
    } else {
        result = PQexec (conn->db_conn, sql);
    }

out:
    if (n > 0){
       for(i = 0; i < n; ++i)
            g_free (v_values[i]);
       
       g_string_free (sql_convert, TRUE);
       g_string_free (stmt_name, TRUE); 
    }
    
    return (PGresult *)result;
}

static int
pgsql_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql)
{
    PGresult *result;
    int ret = 0;

    result =_execute_sql_pgsql(vconn, sql, 0, NULL);
    
    if (!result) {
        ret = -1;
        goto out;
    }
    
    if (PQresultStatus(result) != PGRES_COMMAND_OK 
        && PQresultStatus(result) != PGRES_TUPLES_OK 
        && PQresultStatus(result) != PGRES_EMPTY_QUERY) {
       ccnet_warning ("Failed to execute sql %s: %s\n", sql, PQresultErrorMessage(result));
       ret = -1;
    }

    PQclear(result);
    
out:
    return ret;
}

static int
pgsql_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args)
{
    PGresult *result;
    int ret = 0;
    
    result =_execute_sql_pgsql(vconn, sql, n, args);
    
    if (!result) {
        ret = -1;
        goto out;
    }
    
    if (PQresultStatus(result) != PGRES_COMMAND_OK 
        && PQresultStatus(result) != PGRES_TUPLES_OK 
        && PQresultStatus(result) != PGRES_EMPTY_QUERY) {
       ccnet_warning ("Failed to execute sql %s: %s\n", sql, PQresultErrorMessage(result));
       ret = -1;
    }
    
    PQclear(result);
    
out:
    return ret;
}

typedef struct PostgreSQLDBRow {
    CcnetDBRow parent;
    int column_count;
    int row_idx;
    PGresult *result;
} PostgreSQLDBRow;

static int
pgsql_db_query_foreach_row (DBConnection *vconn,
                            const char *sql, CcnetDBRowFunc callback,
                            void *data, int n, va_list args)
{    
    PGresult *result;
    PostgreSQLDBRow row;
    int i, nrows = 0;

    result = _execute_sql_pgsql(vconn, sql, n, args);
    
    if (!result) {
       nrows = -1;
       goto out;
    }

    if (PQresultStatus(result) != PGRES_COMMAND_OK && PQresultStatus(result) != PGRES_TUPLES_OK) {
       ccnet_warning ("Failed to execute sql %s: %s\n", sql, PQresultErrorMessage(result));
       PQclear(result);
       nrows = -1;
       goto out;
    }
    
    nrows = PQntuples(result);
    if (nrows == 0){ 
        goto out; 
    }
    
    memset (&row, 0, sizeof(row));
    row.column_count = PQnfields(result);
    row.result = result;
    
    for (i = 0; i < nrows; i++) {
        row.row_idx = i;
        if (callback && !callback ((CcnetDBRow *)&row, data))
            break;
    }
    
out:
    return nrows;
}

static int
pgsql_db_row_get_column_count (CcnetDBRow *vrow)
{
    PostgreSQLDBRow *row = (PostgreSQLDBRow *)vrow;
    
    return row->column_count;
}

static const char *
pgsql_db_row_get_column_string (CcnetDBRow *vrow, int idx)
{
    PostgreSQLDBRow *row = (PostgreSQLDBRow *)vrow;
    char *ret;
    
    ret = PQgetvalue(row->result, row->row_idx, idx);
    
    if (strlen(ret) == 0)
        ret = NULL;
    
    return ret;
}

static int
pgsql_db_row_get_column_int (CcnetDBRow *vrow, int idx)
{
    const char *str;
    char *e;
    int ret;

    str = pgsql_db_row_get_column_string (vrow, idx);
    if (!str) {
        return 0;
    }

    errno = 0;
    ret = strtol (str, &e, 10);
    if (errno || (e == str)) {
        ccnet_warning ("Number int conversion failed.\n");
        return -1;
    }

    return ret;
}

static gint64
pgsql_db_row_get_column_int64 (CcnetDBRow *vrow, int idx)
{
    const char *str;
    char *e;
    gint64 ret;

    str = pgsql_db_row_get_column_string (vrow, idx);
    if (!str) {
        return 0;
    }

    errno = 0;
    ret = strtoll (str, &e, 10);
    if (errno || (e == str)) {
        ccnet_warning ("Number int64 conversion failed.\n");
        return -1;
    }

    return ret;
}

#endif

/* SQLite DB */

/* SQLite thread synchronization rountines.
 * See https://www.sqlite.org/unlock_notify.html
 */

typedef struct UnlockNotification {
        int fired;
        pthread_cond_t cond;
        pthread_mutex_t mutex;
} UnlockNotification;

static void
unlock_notify_cb(void **ap_arg, int n_arg)
{
    int i;

    for (i = 0; i < n_arg; i++) {
        UnlockNotification *p = (UnlockNotification *)ap_arg[i];
        pthread_mutex_lock (&p->mutex);
        p->fired = 1;
        pthread_cond_signal (&p->cond);
        pthread_mutex_unlock (&p->mutex);
    }
}

static int
wait_for_unlock_notify(sqlite3 *db)
{
    UnlockNotification un;
    un.fired = 0;
    pthread_mutex_init (&un.mutex, NULL);
    pthread_cond_init (&un.cond, NULL);

    int rc = sqlite3_unlock_notify(db, unlock_notify_cb, (void *)&un);

    if (rc == SQLITE_OK) {
        pthread_mutex_lock(&un.mutex);
        if (!un.fired)
            pthread_cond_wait (&un.cond, &un.mutex);
        pthread_mutex_unlock(&un.mutex);
    }

    pthread_cond_destroy (&un.cond);
    pthread_mutex_destroy (&un.mutex);

    return rc;
}

static int
sqlite3_blocking_step(sqlite3_stmt *stmt)
{
    int rc;
    while (SQLITE_LOCKED == (rc = sqlite3_step(stmt))) {
        rc = wait_for_unlock_notify(sqlite3_db_handle(stmt));
        if (rc != SQLITE_OK)
            break;
        sqlite3_reset(stmt);
    }
    return rc;
}

static int
sqlite3_blocking_prepare_v2(sqlite3 *db, const char *sql, int sql_len, sqlite3_stmt **pstmt, const char **pz)
{
    int rc;
    while (SQLITE_LOCKED == (rc = sqlite3_prepare_v2(db, sql, sql_len, pstmt, pz))) {
        rc = wait_for_unlock_notify(db);
        if (rc != SQLITE_OK)
            break;
    }
    return rc;
}

static int
sqlite3_blocking_exec(sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **), void *arg, char **errmsg)
{
    int rc;
    while (SQLITE_LOCKED == (rc = sqlite3_exec(db, sql, callback, arg, errmsg))) {
        rc = wait_for_unlock_notify(db);
        if (rc != SQLITE_OK)
            break;
    }
    return rc;
}

typedef struct SQLiteDB {
    CcnetDB parent;
    char *db_path;
} SQLiteDB;

typedef struct SQLiteDBConnection {
    DBConnection parent;
    sqlite3 *db_conn;
} SQLiteDBConnection;

static CcnetDB *
sqlite_db_new (const char *db_path)
{
    SQLiteDB *db = g_new0 (SQLiteDB, 1);
    db->db_path = g_strdup(db_path);

    return (CcnetDB *)db;
}

static DBConnection *
sqlite_db_get_connection (CcnetDB *vdb)
{
    SQLiteDB *db = (SQLiteDB *)vdb;
    sqlite3 *db_conn;
    int result;
    const char *errmsg;
    SQLiteDBConnection *conn;

    result = sqlite3_open_v2 (db->db_path, &db_conn, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_SHAREDCACHE, NULL);
    if (result != SQLITE_OK) {
        errmsg = sqlite3_errmsg(db_conn);
        ccnet_warning ("Failed to open sqlite db: %s\n", errmsg ? errmsg : "no error given");
        return NULL;
    }

    conn = g_new0 (SQLiteDBConnection, 1);
    conn->db_conn = db_conn;

    return (DBConnection *)conn;
}

static void
sqlite_db_release_connection (DBConnection *vconn)
{
    if (!vconn)
        return;

    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;

    sqlite3_close (conn->db_conn);

    g_free (conn);
}

static int
sqlite_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    char *errmsg = NULL;
    int rc;

    rc = sqlite3_blocking_exec (conn->db_conn, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        ccnet_warning ("sqlite3_exec failed %s: %s", sql, errmsg ? errmsg : "no error given");
        if (errmsg)
            sqlite3_free (errmsg);
        return -1;
    }

    return 0;
}

static int
_bind_parameters_sqlite (sqlite3 *db, sqlite3_stmt *stmt, int n, va_list args)
{
    int i;
    const char *type;

    for (i = 0; i < n; ++i) {
        type = va_arg (args, const char *);
        if (strcmp(type, "int") == 0) {
            int x = va_arg (args, int);
            if (sqlite3_bind_int (stmt, i+1, x) != SQLITE_OK) {
                ccnet_warning ("sqlite3_bind_int failed: %s\n", sqlite3_errmsg(db));
                return -1;
            }
        } else if (strcmp (type, "int64") == 0) {
            gint64 x = va_arg (args, gint64);
            if (sqlite3_bind_int64 (stmt, i+1, x) != SQLITE_OK) {
                ccnet_warning ("sqlite3_bind_int64 failed: %s\n", sqlite3_errmsg(db));
                return -1;
            }
        } else if (strcmp (type, "string") == 0) {
            const char *s = va_arg (args, const char *);
            if (sqlite3_bind_text (stmt, i+1, s, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
                ccnet_warning ("sqlite3_bind_text failed: %s\n", sqlite3_errmsg(db));
                return -1;
            }
        } else {
            ccnet_warning ("BUG: invalid prep stmt parameter type %s.\n", type);
            g_return_val_if_reached (-1);
        }
    }

    return 0;
}

static int
sqlite_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    sqlite3 *db = conn->db_conn;
    sqlite3_stmt *stmt;
    int rc;
    int ret = 0;

    rc = sqlite3_blocking_prepare_v2 (db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        ccnet_warning ("sqlite3_prepare_v2 failed %s: %s", sql, sqlite3_errmsg(db));
        return -1;
    }

    if (_bind_parameters_sqlite (db, stmt, n, args) < 0) {
        ccnet_warning ("Failed to bind parameters for sql %s\n", sql);
        ret = -1;
        goto out;
    }

    rc = sqlite3_blocking_step (stmt);
    if (rc != SQLITE_DONE) {
        ccnet_warning ("sqlite3_step failed %s: %s", sql, sqlite3_errmsg(db));
        ret = -1;
        goto out;
    }

out:
    sqlite3_finalize (stmt);
    return ret;
}

typedef struct SQLiteDBRow {
    CcnetDBRow parent;
    int column_count;
    sqlite3 *db;
    sqlite3_stmt *stmt;
} SQLiteDBRow;

static int
sqlite_db_query_foreach_row (DBConnection *vconn, const char *sql,
                             CcnetDBRowFunc callback, void *data,
                             int n, va_list args)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    sqlite3 *db = conn->db_conn;
    sqlite3_stmt *stmt;
    int rc;
    int nrows = 0;

    rc = sqlite3_blocking_prepare_v2 (db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        ccnet_warning ("sqlite3_prepare_v2 failed %s: %s", sql, sqlite3_errmsg(db));
        return -1;
    }

    if (_bind_parameters_sqlite (db, stmt, n, args) < 0) {
        ccnet_warning ("Failed to bind parameters for sql %s\n", sql);
        nrows = -1;
        goto out;
    }

    SQLiteDBRow row;
    memset (&row, 0, sizeof(row));
    row.db = db;
    row.stmt = stmt;
    row.column_count = sqlite3_column_count (stmt);

    while (1) {
        rc = sqlite3_blocking_step (stmt);
        if (rc == SQLITE_ROW) {
            ++nrows;
            if (callback && !callback ((CcnetDBRow *)&row, data))
                break;
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            ccnet_warning ("sqlite3_step failed %s: %s\n", sql, sqlite3_errmsg(db));
            nrows = -1;
            goto out;
        }
    }

out:
    sqlite3_finalize (stmt);
    return nrows;
}

static int
sqlite_db_row_get_column_count (CcnetDBRow *vrow)
{
    SQLiteDBRow *row = (SQLiteDBRow *)vrow;

    return row->column_count;
}

static const char *
sqlite_db_row_get_column_string (CcnetDBRow *vrow, int idx)
{
    SQLiteDBRow *row = (SQLiteDBRow *)vrow;

    return (const char *)sqlite3_column_text (row->stmt, idx);
}

static int
sqlite_db_row_get_column_int (CcnetDBRow *vrow, int idx)
{
    SQLiteDBRow *row = (SQLiteDBRow *)vrow;

    return sqlite3_column_int (row->stmt, idx);
}

static gint64
sqlite_db_row_get_column_int64 (CcnetDBRow *vrow, int idx)
{
    SQLiteDBRow *row = (SQLiteDBRow *)vrow;

    return sqlite3_column_int64 (row->stmt, idx);
}
