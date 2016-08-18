/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <time.h>

#include "message.h"
#include "ccnet-db.h"
#include "string-util.h"

static CcnetMessage *
ccnet_message_new_full (const char *from,
                        const char *to,
                        const char *app,
                        const char *body,
                        time_t ctime,
                        time_t rtime,
                        const char *id,
                        char flags)
{
    CcnetMessage *message = g_new0 (CcnetMessage, 1);

    g_return_val_if_fail (flags >= 0, NULL);
    g_return_val_if_fail (from != NULL && to != NULL && app != NULL, NULL);

    message->flags = flags;
    memcpy (message->from, from, 40);
    message->from[40] = '\0';
    memcpy (message->to, to, 40); /* ok if strlen(to) == 36 */
    message->to[40] = '\0';
    message->app = g_intern_string(app);
    message->body = g_strdup(body);
    message->ctime = (ctime ? ctime : time(NULL));
    message->rtime = rtime;
    message->id = (id ? g_strdup (id) : gen_uuid());

    message->ref_count = 1;

    return message;
}

CcnetMessage *
ccnet_message_new (const char *from,
                   const char *to,
                   const char *app,
                   const char *body,
                   char flags)
{
    return ccnet_message_new_full (from, to, app, body, 0, 0, NULL, flags);
}

void
ccnet_message_ref (CcnetMessage *message)
{
    message->ref_count++;
}

void
ccnet_message_unref (CcnetMessage *message)
{
    if (--message->ref_count == 0)
        ccnet_message_free (message);
}

void
ccnet_message_free (CcnetMessage *message)
{
    g_free (message->id);
    g_free (message->body);
    g_free (message);
}

void
ccnet_message_to_string_buf_local (CcnetMessage *msg, GString *buf)
{
    g_string_printf (buf, "%d %s %s %s %d %d %s %s", msg->flags,
                     msg->from, 
                     msg->to,
                     msg->id,
                     (int)msg->ctime,
                     (int)msg->rtime,
                     msg->app,
                     msg->body);
}

void
ccnet_message_to_string_buf (CcnetMessage *msg, GString *buf)
{
    g_string_printf (buf, "%d %s %s %s %d %s %s", msg->flags,
                     msg->from, 
                     msg->to,
                     msg->id,
                     (int)msg->ctime,
                     msg->app,
                     msg->body);
}


CcnetMessage *
ccnet_message_from_string (char *buf, int len)
{
    char flags;
    char *from_id, *to_id, *msg_id, *body, *p, *time, *app;
    int ctime, rcv_time = 0;
    CcnetMessage *message;

    g_return_val_if_fail (END_0(buf,len), NULL);

    p = buf;
    while (*p != ' ' && *p) ++p;
    if (*p != ' ')
        goto error;
    *p = '\0';
    flags = atoi (buf);

    from_id = ++p;
    p += 40;
    if (*p != ' ')
        goto error;
    *p = '\0';

    to_id = ++p;
    p += 40;                /* SHA-1 */
    if (*p != ' ')
        goto error;
    *p = '\0';

    msg_id = ++p;
    p += 36;
    if (*p != ' ')
        goto error;
    *p = '\0';

    time = ++p;
    while (*p != ' ' && *p) ++p;
    if (*p != ' ')
        goto error;
    *p = '\0';
    ctime = atoi (time);

    app = ++p;
    while (*p != ' ' && *p) ++p;
    if (*p != ' ')
        goto error;
    *p = '\0';
    body = p + 1;

    message = ccnet_message_new_full (from_id, to_id,
                                      app, body,
                                      ctime, rcv_time,
                                      msg_id, flags);
    return message;

error:
    return NULL;
}

CcnetMessage *
ccnet_message_from_string_local (char *buf, int len)
{
    int flags;
    char *from_id, *to_id, *msg_id, *body, *p, *time, *app;
    int ctime, rcv_time = 0;
    CcnetMessage *message;

    g_return_val_if_fail (END_0(buf,len), NULL);

    p = buf;
    while (*p != ' ' && *p) ++p;
    if (*p != ' ')
        goto error;
    *p = '\0';
    flags = atoi (buf);

    from_id = ++p;
    p += 40;
    if (*p != ' ')
        goto error;
    *p = '\0';

    to_id = ++p;
    p += 40;                /* SHA-1 */
    if (*p != ' ')
        goto error;
    *p = '\0';

    msg_id = ++p;
    p += 36;
    if (*p != ' ')
        goto error;
    *p = '\0';

    time = ++p;
    while (*p != ' ' && *p) ++p;
    if (*p != ' ')
        goto error;
    *p = '\0';
    ctime = atoi (time);

    time = ++p;
    while (*p != ' ' && *p) ++p;
    if (*p != ' ')
        goto error;
    *p = '\0';
    rcv_time = atoi (time);

    app = ++p;
    while (*p != ' ' && *p) ++p;
    if (*p != ' ')
        goto error;
    *p = '\0';
    body = p + 1;

    message = ccnet_message_new_full (from_id, to_id,
                                      app, body,
                                      ctime, rcv_time,
                                      msg_id, flags);
    return message;

error:
    return NULL;
}

#if 0
CcnetMessage *
ccnet_message_from_db_stmt (CcnetDBRow *stmt)
{
    const char *msg_id, *from, *to, *app, *body, *bloom;
    int ctime, rtime;
    char flags;
    CcnetMessage *message;
    
    flags = ccnet_db_row_get_column_int (stmt, MSG_DB_COLUMN_FLAGS);
    msg_id = (char *)ccnet_db_row_get_column_text (stmt, MSG_DB_COLUMN_MSG_ID);
    from = (char *)ccnet_db_row_get_column_text (stmt, MSG_DB_COLUMN_FROM_ID);
    to = (char *)ccnet_db_row_get_column_text (stmt, MSG_DB_COLUMN_TO_ID);
    bloom = (char *)ccnet_db_row_get_column_text (stmt, MSG_DB_COLUMN_BLOOM);

    ctime = ccnet_db_row_get_column_int (stmt, MSG_DB_COLUMN_CTIME);
    rtime = ccnet_db_row_get_column_int (stmt, MSG_DB_COLUMN_RTIME);
    app = (char *)ccnet_db_row_get_column_text (stmt, MSG_DB_COLUMN_APP);
    body = (char *)ccnet_db_row_get_column_text (stmt, MSG_DB_COLUMN_BODY);
    
    app = g_intern_string(app);

    message = ccnet_message_new_full (from, to,
                                      app, body,
                                      ctime, rtime,
                                      msg_id, flags);

    message->db_id = ccnet_db_row_get_column_int64 (stmt, MSG_DB_COLUMN_DB_ID);
    if (bloom)
        message->bloom = g_strdup(bloom);
    else
        message->bloom = 0;

    return message;
}


void
ccnet_message_to_db (CcnetDB *db, const char *table, CcnetMessage *message)
{
    char *sql;
    sql = ccnet_sql_printf ("INSERT INTO %s VALUES ("
                            "NULL, %u, '%s', '%s', '%s', %Q, %u, %u, %Q, %Q);",
                            table,
                            message->flags,
                            message->id,
                            message->from,
                            message->to,
                            message->bloom, /* may be NULL */
                            message->ctime,
                            message->rtime,
                            message->app,
                            message->body);

    ccnet_db_query (db, sql);
    ccnet_sql_free (sql);
}
#endif  /* 0 */
