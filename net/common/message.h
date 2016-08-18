/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_MESSAGE_H
#define CCNET_MESSAGE_H

#include "common.h"
#include "ccnet-db.h"

enum {
    MSG_TYPE_RECV,
    MSG_TYPE_SYS,
};

enum {
    MSG_DB_COLUMN_DB_ID = 0,
    MSG_DB_COLUMN_FLAGS,        /* "%u" */
    MSG_DB_COLUMN_MSG_ID,       /* "%s" */
    MSG_DB_COLUMN_FROM_ID,      /* "%s" */
    MSG_DB_COLUMN_TO_ID,        /* "%s" */
    MSG_DB_COLUMN_BLOOM,        /* "%s" */
    MSG_DB_COLUMN_CTIME,        /* %u */
    MSG_DB_COLUMN_RTIME,        /* %u */
    MSG_DB_COLUMN_APP,          /* %s */
    MSG_DB_COLUMN_BODY,         /* %s */
    NUM_MSG_DB_COLUMNS
};

#define MESSAGE_ID_LEN  36

typedef struct _CcnetMessage      CcnetMessage;

#define FLAG_IS_ERROR 0x02
#define FLAG_IS_ACK 0x08
#define FLAG_IS_RENDEZVOUS 0x10

struct _CcnetMessage {
    int      ref_count;

    gint64   db_id;
    char     flags;
    char    *id;        /* UUID */
    char     from[41];
    char     to[41];
    int      ctime;             /* creation time */
	int 	 rtime;             /* receive time */

    const char *app;            /* application */
    char       *body;
};


CcnetMessage* ccnet_message_new (const char *from,
                                 const char *to,
                                 const char *app,
                                 const char *body,
                                 char flags);

void ccnet_message_free (CcnetMessage *msg);

void ccnet_message_ref (CcnetMessage *);
void ccnet_message_unref (CcnetMessage *);

void ccnet_message_to_string_buf (CcnetMessage *msg, GString *buf);
void ccnet_message_to_string_buf_local (CcnetMessage *msg, GString *buf);

CcnetMessage *ccnet_message_from_string (char *buf, int len);
CcnetMessage *ccnet_message_from_string_local (char *buf, int len);


#endif
