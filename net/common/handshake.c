/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#ifdef WIN32
    #include <winsock2.h>
#else
    #include <netinet/in.h>
#endif

#include "peer.h"
#include "packet-io.h"
#include "session.h"
#include "handshake.h"

#define DEBUG_FLAG CCNET_DEBUG_CONNECTION
#include "log.h"


#define HANDSHAKE_TIMEOUT 10

/* 
   The purpose of handshake is to obtain the peer's Peer ID.

   Handshake Protocol:

   Master                                    Slave

                   Master's Peer ID          INIT  
             ----------------------------->  
   ID_SENT                                 
                   Slave's Peer ID
            <----------------------------  
                                           ID_RECEIVED
                   ACK
             ---------------------------->
   DONE                                      DONE 

 */

enum {
    UNKNOWN = 0,
    INIT,
    ID_SENT,
    ID_RECEIVED
};

static void ccnet_handshake_done (CcnetHandshake *handshake, int isOK);

static void
send_handshake_message (CcnetHandshake *handshake)
{
    const char *id = handshake->session->base.id;
    char buf[256];
    ccnet_packet *packet = (ccnet_packet *)buf;

    packet->header.version = 1;
    packet->header.type = CCNET_MSG_HANDSHAKE;
    memcpy (packet->data, id, 40);
    packet->header.length = 40;
    packet->header.id = 0;
    
    ccnet_packet_io_write_packet (handshake->io, packet);

    if (handshake->peer)
        ccnet_debug ("[Conn] Outgoing: Send my id to %s(%.10s)\n",
                     handshake->peer->name, handshake->peer->id);
    else
        ccnet_debug ("[Conn] Incoming: Send my id to %.10s\n",
                     handshake->id);
}

static void
send_ack (CcnetHandshake *handshake)
{
    ccnet_packet packet;
    packet.header.version = 1;
    packet.header.type = CCNET_MSG_OK;
    packet.header.length = 0;
    packet.header.id = 0;
    
    ccnet_packet_io_write_packet (handshake->io, &packet);

    ccnet_debug ("[Conn] Outgoing: Send ack to %s(%.10s)\n", 
                 handshake->peer->name, handshake->peer->id);
}

static void
read_peer_id (CcnetHandshake *handshake, ccnet_packet *packet)
{
    uint16_t len;
    char *id;

    /* get id */
    len = packet->header.length;
    id = g_malloc (len + 1);
    memcpy (id, packet->data, len);
    id[len] = '\0';
    handshake->id = id;

    if (handshake->state == INIT) {
        /* we are the slave */
        ccnet_debug ("[Conn] Incoming: Read peer id %.8s\n", id);
        send_handshake_message (handshake);
        handshake->state = ID_RECEIVED;
    } else if (handshake->state == ID_SENT) {
        /* we are the master */
        ccnet_debug ("[Conn] Outgoing: Read peer %s id %.8s\n",
                     handshake->peer->name, id);
        if (g_strcmp0 (handshake->peer->id, handshake->id) != 0) {
            ccnet_warning ("[Conn] Received peer id does not match.\n");
            ccnet_handshake_done (handshake, FALSE);
            return;
        }

        send_ack (handshake);
        ccnet_handshake_done (handshake, TRUE);
    }
}


static void
read_ok (CcnetHandshake *handshake, ccnet_packet *packet)
{
    if (packet->header.type != CCNET_MSG_OK) {
        ccnet_warning ("[Conn] Read wrong ack format\n");
        ccnet_handshake_done (handshake, FALSE);
    } else  {
        ccnet_debug ("[Conn] Incoming: Read ack (%.10s)\n", handshake->id);
        ccnet_handshake_done (handshake, TRUE);
    }
  
    return;
}


static void
canRead (ccnet_packet *packet, void *arg)
{
    CcnetHandshake *handshake = (CcnetHandshake *)arg;
    ccnet_debug("current state is %d\n", handshake->state);

    switch (handshake->state) {
    case INIT:
        read_peer_id (handshake, packet);
        break;
    case ID_SENT:
        read_peer_id (handshake, packet);
        break;
    case ID_RECEIVED:
        read_ok (handshake, packet);
        break;
    default:
        g_return_if_reached ();
    }
}

static void
fire_done_func (CcnetHandshake *handshake, int is_connected)
{
    const char * peer_id;

    peer_id = is_connected ? handshake->id : NULL;
    
    (*handshake->doneCB) (handshake,
                          handshake->io,
                          is_connected,
                          peer_id,
                          handshake->doneUserData);
}

static void
ccnet_handshake_done (CcnetHandshake *handshake, int isOK)
{
    /* ccnet_message ("handshakeDone: %s\n", isOK ? "connected" : "aborting"); */
    ccnet_debug ("[Conn] HandshakeDone %s\n", isOK ? "connected" : "aborting");

    ccnet_packet_io_set_iofuncs (handshake->io, NULL, NULL, NULL, NULL);
    fire_done_func (handshake, isOK);
    if (handshake->peer)
        g_object_unref (handshake->peer);
    g_free (handshake->id);
    g_free (handshake);
}

void
ccnet_handshake_abort (CcnetHandshake * handshake)
{
    ccnet_handshake_done (handshake, FALSE);
}

#include <errno.h>

static void
gotError (struct bufferevent * evbuf, short what, void *arg)
{
    CcnetHandshake * handshake = (CcnetHandshake *) arg;

    /* if the error happened while we were sending a public key, we might
     * have encountered a peer that doesn't do encryption... reconnect and
     * try a plaintext handshake */
    /* ccnet_warning ("libevent got an error on peer %s what==%d, errno=%d (%s)\n",
                   handshake->peer ? handshake->peer->name : "(no-id)",
                   (int)what, errno, strerror(errno)); */
    ccnet_handshake_abort (handshake);
}


CcnetHandshake*
ccnet_handshake_new (CcnetSession     *session,
                     CcnetPeer        *peer,
                     CcnetPacketIO    *io,
                     handshakeDoneCB   doneCB,
                     void             *doneUserData)
{
    CcnetHandshake * handshake;

    handshake = g_new0 (CcnetHandshake, 1);
    handshake->peer = peer;
    if (peer)
        g_object_ref (peer);
    handshake->io = io;
    handshake->doneCB = doneCB;
    handshake->doneUserData = doneUserData;
    handshake->session = session;

    ccnet_packet_io_set_timeout_secs (io, HANDSHAKE_TIMEOUT);
    ccnet_packet_io_set_iofuncs (handshake->io, canRead, NULL,
                                 gotError, handshake);

    if (ccnet_packet_io_is_incoming (handshake->io))
        handshake->state = INIT;
    else {
        send_handshake_message (handshake);
        handshake->state = ID_SENT;
    }

    return handshake;
}
