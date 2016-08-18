/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "session.h"
#include "peer.h"
#include "peer-mgr.h"
#include "utils.h"
#include "peermgr-message.h"

#define DEBUG_FLAG CCNET_DEBUG_PEER
#include "log.h"


/*
Protocol v1:

  PeermgrMessage format:
        v<num>\n
        <type>\n
        [content]

  For example:
        v1\n
        role-notify\n
        MyPeer\n

 */


int
parse_peermgr_message (CcnetMessage *msg, guint16 *version,
                       char **type, char **body)
{
    char *end, *start;
    int v;

    if (!msg->body)
        return -1;

    /* version */
    if (msg->body[0] != 'v')
        return -1;

    start = msg->body + 1;
    if ( !(end = strchr(start, '\n')) ) return -1;
    *end = '\0';
    if ((v = atoi(start)) == 0) return -1;
    *version = v;

    /* type */
    *type = start = end + 1;
    if ( !(end = strchr(start, '\n')) ) return -1;
    *end = '\0';
    
    *body = start = end + 1;
    return 0;
}
