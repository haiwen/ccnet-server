/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_ALGORITHMS_H
#define CCNET_ALGORITHMS_H

void ccnet_send_message (CcnetSession *session, CcnetMessage *msg);
int ccnet_recv_message (CcnetSession *session, CcnetMessage *msg);


#endif
