/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_HANDSHAKE_H
#define CCNET_HANDSHAKE_H

struct CcnetPacketIO;
typedef struct CcnetHandshake CcnetHandshake;

#include "peer.h"


typedef void (*handshakeDoneCB) (CcnetHandshake *handshake,
                                 CcnetPacketIO  *io,
                                 int             isConnected,
                                 const char     *peerId,
                                 void           *userData);

struct CcnetHandshake
{
    char   *id;                  /* the peer id */
    CcnetPeer             *peer;  /* only valid if it is outgoing */
    CcnetPacketIO         *io;
    struct CcnetSession *session;

    uint8_t state;

    handshakeDoneCB doneCB;
    void   *doneUserData;
};

CcnetHandshake* ccnet_handshake_new (CcnetSession *session,
                                     CcnetPeer *peer,
                                     CcnetPacketIO *io,
                                     handshakeDoneCB doneCB,
                                     void *doneUserData);


#endif
