/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdio.h>
#include <event2/util.h>

#include "net.h"
#include "packet.h"
#include "packet-io.h"
#include "peer.h"
#include "session.h"
#include "handshake.h"
#include "message.h"
#include "peer-mgr.h"
#include "connect-mgr.h"
#include "message-manager.h"
#include "proc-factory.h"


#define MAX_RECONNECTIONS_PER_PULSE  5
#define LISTEN_INTERVAL 1000        /* 1s */
#define RECONNECT_PERIOD_MSEC             10000


#define DEBUG_FLAG CCNET_DEBUG_CONNECTION
#include "log.h"

extern void ccnet_peer_set_net_state (CcnetPeer *peer, int net_state);
extern gboolean
ccnet_peer_manager_on_peer_resolved (CcnetPeerManager *manager,
                                     CcnetPeer *peer);
extern void
ccnet_peer_manager_on_peer_resolve_failed (CcnetPeerManager *manager,
                                           CcnetPeer *peer);

static void dns_lookup_peer (CcnetPeer* peer);

CcnetConnManager *
ccnet_conn_manager_new (CcnetSession *session)
{
    CcnetConnManager *manager;

    manager = g_new0 (CcnetConnManager, 1);
    manager->session = session;

    return manager;
}

#if 0
/* Note: The handshake timeout is 10s.
 *       So intervals[0] must be larger than 10s to
 *       prevent simultaneously connection tryings.
 *       Actually any value larger than 10 is ok.
 *       Here we just set it to 20s.
 */
static int intervals[] = {
    20,                     
    30,
    60,
    15 * 60,
    30 * 60,
    60 * 60,
};

static int
get_reconnect_interval_secs (const CcnetPeer *peer)
{
    if (peer->is_relay)
        return intervals[0];
    int index = MIN (peer->num_fails, G_N_ELEMENTS(intervals) - 1);
    return intervals[index];
}
#endif

void start_keepalive (CcnetPeer *peer)
{
    CcnetProcessor *processor;
    CcnetProcFactory *factory = peer->manager->session->proc_factory;
    
    processor = ccnet_proc_factory_create_master_processor (factory,
                                                    "keepalive2", peer);
    if (processor == NULL) {
        ccnet_warning ("Create keepalive2 processor failed\n");
        return;
    }
    ccnet_processor_startl (processor, NULL);
}

static void on_peer_connected (CcnetPeer *peer, CcnetPacketIO *io)
{
    g_return_if_fail (peer->net_state == PEER_DOWN);

    ccnet_peer_set_io (peer, io);
    ccnet_peer_set_net_state (peer, PEER_CONNECTED);
    start_keepalive (peer);
}

static void notify_found_peer (CcnetSession *session, CcnetPeer *peer)
{
    char buf[128];

    sprintf (buf, "found %s\n", peer->id);
    CcnetMessage *message = ccnet_message_new (session->base.id,
                                               session->base.id,
                                               "System", buf, 0);
    ccnet_message_manager_add_msg (session->msg_mgr,
                                   message, MSG_TYPE_SYS);
    
}

static void on_get_resolve_peer_pub_info_done (CcnetProcessor *processor,
                                               gboolean success, void *data)
{
    if (success) {
        gboolean should_continue;
        should_continue = ccnet_peer_manager_on_peer_resolved (
            processor->peer->manager, processor->peer);
        if (!should_continue)
            return;
        start_keepalive (processor->peer);
    } else {
        ccnet_message ("Get resolved peer pub info failed\n");
        ccnet_peer_manager_on_peer_resolve_failed (
            processor->peer->manager, processor->peer);
    }
}

static void on_resolve_peer_connected (CcnetPeer *peer, CcnetPacketIO *io)
{
    CcnetProcessor *processor;
    CcnetProcFactory *factory = peer->manager->session->proc_factory;

    ccnet_peer_set_io (peer, io);              
    ccnet_peer_set_net_state (peer, PEER_CONNECTED);

    processor = ccnet_proc_factory_create_master_processor (
        factory, "get-pubinfo", peer);
    if (processor == NULL) {
        ccnet_warning ("Create get-pubinfo processor failed\n");
        ccnet_peer_shutdown (peer);
        return;
    }
    g_signal_connect (processor, "done",
                      G_CALLBACK(on_get_resolve_peer_pub_info_done), NULL);

    ccnet_processor_startl (processor, NULL);
}

static void on_get_unauth_peer_pub_info_done (CcnetProcessor *processor,
                                              gboolean success, void *data)
{
    if (success) {
        notify_found_peer (processor->session, processor->peer);
        start_keepalive (processor->peer);
    } else
        ccnet_peer_shutdown (processor->peer);
}

static void on_unauthed_peer_connected (CcnetPeer *peer, CcnetPacketIO *io)
{
    CcnetProcessor *processor;
    CcnetProcFactory *factory = peer->manager->session->proc_factory;

    ccnet_peer_set_io (peer, io);              
    ccnet_peer_set_net_state (peer, PEER_CONNECTED);

    processor = ccnet_proc_factory_create_master_processor (
        factory, "get-pubinfo", peer);
    if (processor == NULL) {
        ccnet_warning ("Create get-pubinfo processor failed\n");
        ccnet_peer_shutdown (peer);
        return;
    }
    g_signal_connect (processor, "done",
                      G_CALLBACK(on_get_unauth_peer_pub_info_done), NULL);

    ccnet_processor_startl (processor, NULL);
}

static void set_peer_address_from_socket(CcnetPeer *peer, CcnetPacketIO *io)
{
    if (peer == NULL || io == NULL)
        return;

    if (peer->addr_str)
        g_free (peer->addr_str);

    struct sockaddr_in addr;
    socklen_t len = sizeof(struct sockaddr_in);
    int socket = io->socket;
    getpeername (socket, (struct sockaddr *)&addr, &len);
    char *p = inet_ntoa (addr.sin_addr);
    peer->addr_str = strdup(p);
}

static void
myHandshakeDoneCB (CcnetHandshake *handshake,
                   CcnetPacketIO  *io,
                   int             is_connected,
                   const char     *peer_id,
                   void           *vmanager)
{
    CcnetConnManager *manager = vmanager;
    CcnetPeerManager *peerMgr = manager->session->peer_mgr;
    CcnetPeer *peer;

    if (!is_connected) {
        if (ccnet_packet_io_is_incoming (io)) {
            ccnet_warning ("[conn] incoming handshake fails.\n");
            ccnet_packet_io_free (io);
            return;
        }

        /* temporally use peer, so don't need to increase the reference */
        peer = handshake->peer;
        if (peer->num_fails == 0) {
            /* print error for the first time */
            ccnet_message ("[Conn] peer %s(%.10s) connection fails\n", 
                         peer->name, peer->id);
        } else {
            ccnet_debug ("[Conn] peer %s(%.10s) connection fails\n", 
                         peer->name, peer->id);
        }
        if (peer->net_state == PEER_CONNECTED) {
            ccnet_debug ("[Conn] But Peer %s(%.10s) is already connected me.\n",
                         peer->name, peer->id);
        } else if (peer->net_state == PEER_DOWN){
            ccnet_peer_shutdown(peer);
        }

        ccnet_packet_io_free (io);

        peer->num_fails++;
        peer->in_connection = 0;
        return;
    }

    if (!ccnet_packet_io_is_incoming (io)) {
        peer = handshake->peer;
        peer->in_connection = 0;
        
        if (peer->to_resolve) {
            if (!peer_id_valid(peer_id)) {
                /* TODO: Remove the peer */
                ccnet_warning ("[Conn] Resolving: Received invalid peer id\n");
                return;
            }
            ccnet_debug ("[Conn] Resolving: Peer %.8s is resolved\n", peer_id);
            memcpy (peer->id, peer_id, 40);
            peer->id[40] = '\0';
            on_resolve_peer_connected (peer, io);
            return;
        }
        /* ref for using the peer below */
        g_object_ref (peer);
    } else {
        /* incoming */
        if (!peer_id_valid (peer_id)) {
            ccnet_warning ("Invalid peer (no-id) connecting\n");
            ccnet_packet_io_free (io);
            return;
        }
        peer = ccnet_peer_manager_get_peer (peerMgr, peer_id);
        if (!peer) {
            ccnet_message ("Unknown peer %s connecting\n", peer_id);
            peer = ccnet_peer_new (peer_id);
            ccnet_peer_manager_add_peer (peerMgr, peer);
            set_peer_address_from_socket(peer, io);
            peer->last_up = time(NULL);
            on_unauthed_peer_connected (peer, io);
            g_object_unref (peer);
            return;
        }

        if (peer->net_state == PEER_CONNECTED) {
            ccnet_message ("[Conn] Peer %s (%.10s) is already connected."
                           "But a new handshake comes in. Reconnect this peer.\n",
                           peer->name, peer->id);
            ccnet_peer_shutdown_no_delay (peer);
        }

        set_peer_address_from_socket(peer, io);
        peer->last_up = time(NULL);
    }
    /* hold a reference on the peer */

    ccnet_message ("[Conn] Peer %s (%.10s) connected\n",
                   peer->name, peer->id);
    peer->num_fails = 0;
    on_peer_connected (peer, io);
    g_object_unref (peer);
}


/**
 * return %TRUE if an outgoing connection is started, %FALSE otherwise.
 *
 * When peer's ip address is not looked up yet, an dns request will be sent,
 * and when dns done, this function will be called again.
 */
gboolean
ccnet_conn_manager_connect_peer (CcnetConnManager *manager, CcnetPeer *peer)
{
    CcnetPacketIO *io;
    /* int interval; */
    const char *addr = NULL;
    int port = 0;

    if (peer->in_connection)
        return FALSE;

    /* time_t now = time(NULL); */
    
    if (peer->net_state == PEER_CONNECTED)
        return FALSE;

    if (peer->dns_addr)
        addr = peer->dns_addr;
    else if (!peer->redirected) {
        if (!peer->public_addr)
            goto err_connect;

        if (is_valid_ipaddr(peer->public_addr))
            addr = peer->public_addr;
        else {
            dns_lookup_peer (peer);
            return TRUE;        /* same as out going is started */
        }
    } else {
        if (!peer->redirect_addr)
            goto err_connect;

        if (is_valid_ipaddr(peer->redirect_addr))
            addr = peer->redirect_addr;
        else {
            dns_lookup_peer (peer);
            return TRUE;        /* same as out going is started */
        }
    }

    if (!addr)
        goto err_connect;

    if (!peer->redirected)
        port = peer->public_port;
    else
        port = peer->redirect_port;

    ccnet_peer_update_address (peer, addr, port);

    /* interval = get_reconnect_interval_secs (peer); */
    /* if (now - peer->last_try_time < interval) { */
        /* ccnet_debug ("[Conn] Less than interval: (%d - %d = %d, %d)\n", */
        /*              now, peer->last_try_time, now - peer->last_try_time, */
        /*              interval); */
    /*     return FALSE; */
    /* } */
    /* peer->last_try_time = now; */

    if (peer->num_fails == 0) {
        /* print log for the first time */
        ccnet_message ("[Conn] Start outgoing connect to %s(%.10s) %s:%d\n", 
                       peer->name, peer->id, addr, port);
    } else {
        ccnet_debug ("[Conn] Start outgoing connect to %s(%.10s) %s:%d\n", 
                     peer->name, peer->id, addr, port);
    }
    io = ccnet_packet_io_new_outgoing (manager->session, addr, port);
    
    if (io == NULL) {
        /* ccnet_warning ("Failed to create socket for peer %s (%.10s)\n", 
           peer->name, peer->id); */
        goto err_connect;
    } else {
        peer->in_connection = 1;
        ccnet_handshake_new (manager->session, peer, io, 
                             myHandshakeDoneCB, manager);
        return TRUE;
    }

err_connect:
    peer->num_fails++;
    return FALSE;
}

static void
reconnect_peer (CcnetConnManager *manager, CcnetPeer *peer)
{
    if (peer->net_state == PEER_CONNECTED || peer->in_connection)
        return;
/*
    if (peer->public_addr == NULL) {
        ccnet_warning ("[conn-mgr] A peer without public_ip and "
                       "domain is entered in conn_list\n");
        return;
    }
*/
    ccnet_conn_manager_connect_peer (manager, peer);
}

static int reconnect_pulse (void *vmanager)
{
    CcnetConnManager *manager = vmanager;
    /* int conn = 0; */
    GList  *ptr;

#ifndef CCNET_SERVER
    GList *peers = ccnet_peer_manager_get_peers_with_role (
        manager->session->peer_mgr, "MyRelay");
    for (ptr = peers; ptr; ptr = ptr->next) {
        CcnetPeer *peer = ptr->data;
        if (peer->redirected) {
            if (peer->num_fails > 2)
                ccnet_peer_unset_redirect (peer);
        }
        reconnect_peer (manager, peer);
        g_object_unref (peer);
    }
    g_list_free (peers);
#endif

    for (ptr = manager->conn_list; ptr; ptr = ptr->next) {
        CcnetPeer *peer = ptr->data;
        if (peer->redirected) {
            if (peer->num_fails > 2)
                ccnet_peer_unset_redirect (peer);
        }
        reconnect_peer (manager, peer);
    }

    /*
    peers = ccnet_peer_manager_get_peers_with_role (
        manager->session->peer_mgr, "MyPeer");
    for (ptr = peers; ptr; ptr = ptr->next) {
        CcnetPeer *peer = ptr->data;

        if (peer->is_self)
            continue;

        if (!peer->is_relay && !ccnet_peer_is_mypeer(peer))
            continue;

        if (ccnet_conn_manager_connect_peer (manager, peer) == FALSE)
            continue;

        if (++conn >= MAX_RECONNECTIONS_PER_PULSE)
            break;
    }
    g_list_free (peers);
    */

    /* TODO: teer down connections */
    
    return TRUE;
}

void
ccnet_conn_manager_add_incoming (CcnetConnManager    *manager,
                                 struct sockaddr_storage *cliaddr,
                                 size_t            addrlen,
                                 evutil_socket_t   socket)
{
    CcnetPacketIO *io;
    
    io = ccnet_packet_io_new_incoming (manager->session, cliaddr, socket);
    ccnet_handshake_new (manager->session, NULL, io,
                         myHandshakeDoneCB, manager);
}


static int
listen_pulse (void * vmanager)
{
    CcnetConnManager *manager = vmanager;

    for ( ;; ) /* check for new incoming peer connections */    
    {
        evutil_socket_t socket;
        struct sockaddr_storage cliaddr;
        socklen_t len = sizeof (struct sockaddr_storage);

        if (manager->bind_socket < 0)
            break;

        if ((socket = ccnet_net_accept (manager->bind_socket, 
                                        &cliaddr, &len, 1)) < 0)
            break;

        ccnet_conn_manager_add_incoming (manager, &cliaddr, len, socket);
    }
 
    return TRUE;
}


#ifndef CCNET_SERVER
#endif  /* ifndef CCNET_SERVER */


void
ccnet_conn_listen_init (CcnetConnManager *manager)
{
    evutil_socket_t socket;
    CcnetSession *session = manager->session;

    if (session->base.public_port == 0) {
        ccnet_message ("Do not listen for incoming peers\n");
        return;
    }

    socket = ccnet_net_bind_tcp (session->base.public_port, 1);
    if (socket >= 0) {
        ccnet_message ("Opened port %d to listen for "
                       "incoming peer connections\n", session->base.public_port);
        manager->bind_socket = socket;
        listen (manager->bind_socket, 5);
    } else {
        ccnet_error ("Couldn't open port %d to listen for "
                     "incoming peer connections (errno %d - %s)",
                     session->base.public_port, errno, strerror(errno) );
        exit (1);
    }

    manager->listen_timer = ccnet_timer_new (listen_pulse, manager,
                                             LISTEN_INTERVAL);
}

typedef struct DNSLookupData {
    CcnetPeer *peer;
    char *addr_str;
} DNSLookupData;

static void *
dns_lookup (void *vdata)
{
    DNSLookupData *data = vdata;
    struct evutil_addrinfo hints;
    struct evutil_addrinfo *answer = NULL;
    int err;
    void *addr;
    char *addr_str;
    socklen_t size;

    /* Build the hints to tell getaddrinfo how to act. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* only use IPv4 now. */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP; /* We want a TCP socket */
    /* Only return addresses we can use. */
    hints.ai_flags = EVUTIL_AI_ADDRCONFIG;

    /* Look up the hostname. */
    err = evutil_getaddrinfo(data->peer->public_addr, NULL, &hints, &answer);
    if (err != 0) {
          ccnet_warning("Error while resolving '%s': %s\n",
                        data->peer->public_addr, evutil_gai_strerror(err));
          return vdata;
    }

    /* just use the first answer */
    if (answer->ai_family == AF_INET) {
        size = INET_ADDRSTRLEN;
        addr = &((struct sockaddr_in *)(answer->ai_addr))->sin_addr;
    } else if (answer->ai_family == AF_INET6) {
        size = INET6_ADDRSTRLEN;
        addr = &((struct sockaddr_in6 *)(answer->ai_addr))->sin6_addr;
    } else
        goto out;

    addr_str = (char *)calloc(size, sizeof(char));
    if (addr_str == NULL) {
        ccnet_error("Out of memory\n");
        goto out;
    }

    if (!evutil_inet_ntop(answer->ai_family, addr, addr_str, size)) {
        ccnet_warning("Peer %s domain name %s lookup fail\n",
                      data->peer->name, data->peer->public_addr);
        free(addr_str);
        goto out;
    }

    data->addr_str = addr_str;

out:
    evutil_freeaddrinfo (answer);
    return vdata;
}

static void
dns_lookup_cb (void *result)
{
    DNSLookupData *data = result;
    CcnetPeer *peer = data->peer;

    if (!data->addr_str) {
        ccnet_warning ("DNS lookup failed for peer %.10s(%s).\n",
                       data->peer->id, data->peer->public_addr);
        g_free (data);
        return;
    }

    g_free(peer->dns_addr);
    peer->dns_addr = g_strdup (data->addr_str);
    peer->dns_done = 1;
    ccnet_conn_manager_connect_peer (peer->manager->session->connMgr, peer);

    free(data->addr_str);
    g_free (data);
}

static void
dns_lookup_peer (CcnetPeer* peer)
{
    DNSLookupData *data;

    if (peer->dns_done)
        return;

    data = g_new0 (DNSLookupData, 1);
    data->peer = peer;
    ccnet_job_manager_schedule_job (peer->manager->session->job_mgr,
                                    dns_lookup,
                                    dns_lookup_cb,
                                    data);
}

void
ccnet_conn_manager_start (CcnetConnManager *manager)
{
#ifdef CCNET_SERVER
    ccnet_conn_listen_init (manager);
#endif
    manager->reconnect_timer = ccnet_timer_new (reconnect_pulse, manager,
                                                RECONNECT_PERIOD_MSEC);
}

void
ccnet_conn_manager_stop (CcnetConnManager *manager)
{
    evutil_closesocket (manager->bind_socket);
    manager->bind_socket = 0;

    ccnet_timer_free (&manager->reconnect_timer);
    ccnet_timer_free (&manager->listen_timer);
}

void
ccnet_conn_manager_add_to_conn_list (CcnetConnManager *manager,
                                     CcnetPeer *peer)
{
    if (g_list_find (manager->conn_list, peer)) {
        ccnet_warning ("[Conn] peer %s(%.8s) is already in conn_list\n",
                       peer->name, peer->id);
        return;
    }
    manager->conn_list = g_list_prepend (manager->conn_list, peer);
    g_object_ref (peer);
}

void
ccnet_conn_manager_remove_from_conn_list (CcnetConnManager *manager,
                                          CcnetPeer *peer)
{
    /* we can't directly use g_list_remove, since we have to call
     * g_object_unref, if the peer is actually in the list
     */
    if (!g_list_find (manager->conn_list, peer))
        return;
    manager->conn_list = g_list_remove (manager->conn_list, peer);
    g_object_unref (peer);
}

void
ccnet_conn_manager_cancel_conn (CcnetConnManager *manager,
                                const char *addr, int port)
{
    GList *ptr;

    for (ptr = manager->conn_list; ptr; ptr = ptr->next) {
        CcnetPeer *peer = ptr->data;
        if (g_strcmp0(peer->public_addr, addr) == 0 && peer->public_port == port) {
            manager->conn_list = g_list_delete_link (manager->conn_list, ptr);
            if (peer->to_resolve) {
                ccnet_peer_manager_on_peer_resolve_failed (
                    manager->session->peer_mgr, peer);
            }
            g_object_unref (peer);
            break;
        }
    }
}
