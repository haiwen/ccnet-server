/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_PEERMGR_MESSAGE_H
#define CCNET_PEERMGR_MESSAGE_H

#include "message.h"

#define PEERMGR_VERSION   3

#define BIND_QUERY         "bind-query"
#define BIND_STATUS        "bind-status"
#define ROLE_NOTIFY        "role-notify"
#define SERVICE_READY      "service-ready"
#define PEER_REDIRECT      "redirect"

int parse_peermgr_message (CcnetMessage *msg, guint16 *version,
                           char **type, char **body);

#endif
