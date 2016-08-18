/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_PEER_H
#define CCNET_PEER_H


#include <glib.h>
#include <glib-object.h>
#include <openssl/rsa.h>

#include "processor.h"


#define CCNET_TYPE_PEER                  (ccnet_peer_get_type ())
#define CCNET_PEER(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_PEER, CcnetPeer))
#define CCNET_IS_PEER(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_PEER))
#define CCNET_PEER_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_PEER, CcnetPeerClass))
#define CCNET_IS_PEER_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_PEER))
#define CCNET_PEER_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_PEER, CcnetPeerClass))


enum {
    PEER_DOWN,
    PEER_CONNECTED
};


typedef struct _CcnetPeer CcnetPeer;
typedef struct _CcnetPeerClass CcnetPeerClass;


struct CcnetPacketIO;

#define NON_RESOLVED_PEERID  "0000000000000000000000000000000000000000"

struct _CcnetUser;

struct _CcnetPeer
{
    GObject       parent_instance;

    /* fields from pubinfo */
    char          id[41];

    RSA          *pubkey;
    char         *session_key;
    unsigned char key[32];
    unsigned char iv[32];

    char         *name;         /* hostname */
    char         *public_addr;
    uint16_t      public_port;  /* port from pubinfo */
    char         *service_url;

    /* fields not from pubinfo */
    char         *addr_str;     /* hold the ip actually used in connection */
    uint16_t      port;

    char         *redirect_addr;
    uint16_t      redirect_port;

    char         *dns_addr;     /* address solved by dns */

    int           net_state;

    GList        *role_list;
    GList        *myrole_list;  /* my role on this peer */

    char         *intend_role;  /* used in peer resolving */

    unsigned int  is_self : 1;
    unsigned int  is_local : 1;
    unsigned int  can_connect : 1;
    unsigned int  in_local_network : 1;

    unsigned int  is_ready : 1;
    unsigned int  dns_done : 1;
    unsigned int  need_saving : 1;

    unsigned int  want_tobe_relay : 1; /* is the peer used as relay */

    unsigned int  in_shutdown : 1;
    unsigned int  shutdown_scheduled : 1;
    unsigned int  in_writecb  : 1;
    unsigned int  in_connection : 1;
    unsigned int  keepalive_sending : 1;

    unsigned int  to_resolve : 1; /* the peer's identity need to be resolved,
                                   * we only have its IP address now.
                                   */

    unsigned int  redirected : 1;

    unsigned int  cluster_member : 1;

    unsigned int  in_processor_call : 1;

    unsigned int  encrypt_channel : 1;

    struct CcnetPacketIO  *io;


    int      last_net_state;

    /* for connection management */
    time_t   last_down;         /* for peer gc in relay */
    int      num_fails;

    int      reqID;

    struct _CcnetPeerManager *manager;

    struct evbuffer      *packet;
    
    GHashTable *processors;

    GList      *write_cbs;

    int         last_mult_recv;

    /* statistics */
    time_t      last_up;
};

struct _CcnetPeerClass
{
    GObjectClass    parent_class;
};

GType ccnet_peer_get_type (void);

CcnetPeer*  ccnet_peer_from_string (char *content);
void        ccnet_peer_update_from_string (CcnetPeer *peer, char *string);
GString *   ccnet_peer_to_string (CcnetPeer *peer);

CcnetPeer*  ccnet_peer_new (const char *id);
void        ccnet_peer_free (CcnetPeer *peer);

void        ccnet_peer_shutdown (CcnetPeer *peer);

void        ccnet_peer_shutdown_no_delay (CcnetPeer *peer);

int         ccnet_peer_get_request_id (CcnetPeer *peer);

void        ccnet_peer_add_processor (CcnetPeer *peer, 
                                      CcnetProcessor *processor);
void        ccnet_peer_remove_processor (CcnetPeer *peer, 
                                         CcnetProcessor *processor);
CcnetProcessor *
            ccnet_peer_get_processor (CcnetPeer *peer, unsigned int id);

void        ccnet_peer_set_net_state (CcnetPeer *peer, int net_state);

void        ccnet_peer_update_address (CcnetPeer *peer,
                                       const char *addr_str,
                                       uint16_t port);

void        ccnet_peer_set_pubkey (CcnetPeer *peer, char *str);

int         ccnet_peer_prepare_channel_encryption (CcnetPeer *peer);

/* role management */
void
ccnet_peer_set_roles (CcnetPeer *peer, const char *roles);

void
ccnet_peer_set_myroles (CcnetPeer *peer, const char *roles);

void
ccnet_peer_get_roles_str (CcnetPeer *peer, GString *buf);

void
ccnet_peer_get_myroles_str (CcnetPeer *peer, GString *buf);

void
ccnet_peer_add_role (CcnetPeer *peer, const char *role);

void
ccnet_peer_remove_role (CcnetPeer *peer, const char *role);

gboolean
ccnet_peer_has_role (CcnetPeer *peer, const char *role);

gboolean
ccnet_peer_has_my_role (CcnetPeer *peer, const char *role);



/*  */
typedef gboolean (*PeerWriteCallback) (CcnetPeer *peer, void *user_data);

void        ccnet_peer_add_write_callback (CcnetPeer *peer,
                                           PeerWriteCallback func,
                                           void *user_data);

void        ccnet_peer_remove_write_callback (CcnetPeer *peer,
                                              PeerWriteCallback func,
                                              void *user_data);

/* IO */
void        ccnet_peer_send_request (const CcnetPeer *peer,
                                     int req_id, const char *req);
void        ccnet_peer_send_response (const CcnetPeer *peer, int req_id,
                                      const char *code, const char *reason,
                                      const char *content, int clen);
void        ccnet_peer_send_update (const CcnetPeer *peer, int req_id,
                                    const char *code, const char *reason,
                                    const char *content, int clen);

/* middle level IO */

void        ccnet_peer_set_io (CcnetPeer *peer, struct CcnetPacketIO *io);

void
ccnet_peer_set_redirect (CcnetPeer *peer, const char *addr, uint16_t port);

void
ccnet_peer_unset_redirect (CcnetPeer *peer);

#endif
