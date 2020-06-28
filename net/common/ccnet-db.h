#ifndef CCNET_DB_H
#define CCNET_DB_H

#define DB_SQLITE "sqlite"
#define DB_MYSQL "mysql"
#define DB_PGSQL "pgsql"

enum {
    CCNET_DB_TYPE_SQLITE,
    CCNET_DB_TYPE_MYSQL,
    CCNET_DB_TYPE_PGSQL,
};

typedef struct CcnetDB CcnetDB;
typedef struct CcnetDBRow CcnetDBRow;
typedef struct CcnetDBTrans CcnetDBTrans;

typedef gboolean (*CcnetDBRowFunc) (CcnetDBRow *, void *);

CcnetDB *
ccnet_db_new_mysql (const char *host,
                    int port,
                    const char *user, 
                    const char *passwd,
                    const char *db,
                    const char *unix_socket,
                    gboolean use_ssl,
                    const char *charset,
                    int max_connections);


CcnetDB *
ccnet_db_new_pgsql (const char *host,
                    unsigned int port,
                    const char *user,
                    const char *passwd,
                    const char *db_name,
                    const char *unix_socket,
                    int max_connections);


CcnetDB *
ccnet_db_new_sqlite (const char *db_path);

int
ccnet_db_type (CcnetDB *db);

int
ccnet_db_query (CcnetDB *db, const char *sql);

gboolean
ccnet_db_check_for_existence (CcnetDB *db, const char *sql, gboolean *db_err);

int
ccnet_db_foreach_selected_row (CcnetDB *db, const char *sql, 
                               CcnetDBRowFunc callback, void *data);

const char *
ccnet_db_row_get_column_text (CcnetDBRow *row, guint32 idx);

int
ccnet_db_row_get_column_int (CcnetDBRow *row, guint32 idx);

gint64
ccnet_db_row_get_column_int64 (CcnetDBRow *row, guint32 idx);

int
ccnet_db_get_int (CcnetDB *db, const char *sql);

gint64
ccnet_db_get_int64 (CcnetDB *db, const char *sql);

char *
ccnet_db_get_string (CcnetDB *db, const char *sql);

/* Transaction related */

CcnetDBTrans *
ccnet_db_begin_transaction (CcnetDB *db);

void
ccnet_db_trans_close (CcnetDBTrans *trans);

int
ccnet_db_commit (CcnetDBTrans *trans);

int
ccnet_db_rollback (CcnetDBTrans *trans);

int
ccnet_db_trans_query (CcnetDBTrans *trans, const char *sql, int n, ...);

gboolean
ccnet_db_trans_check_for_existence (CcnetDBTrans *trans,
                                    const char *sql,
                                    gboolean *db_err,
                                    int n, ...);

int
ccnet_db_trans_foreach_selected_row (CcnetDBTrans *trans, const char *sql,
                                     CcnetDBRowFunc callback, void *data,
                                     int n, ...);

/* Prepared Statements */

int
ccnet_db_statement_query (CcnetDB *db, const char *sql, int n, ...);

gboolean
ccnet_db_statement_exists (CcnetDB *db, const char *sql, gboolean *db_err, int n, ...);

int
ccnet_db_statement_foreach_row (CcnetDB *db, const char *sql,
                                CcnetDBRowFunc callback, void *data,
                                int n, ...);

int
ccnet_db_statement_get_int (CcnetDB *db, const char *sql, int n, ...);

gint64
ccnet_db_statement_get_int64 (CcnetDB *db, const char *sql, int n, ...);

char *
ccnet_db_statement_get_string (CcnetDB *db, const char *sql, int n, ...);

#endif
