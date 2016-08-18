/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_PEER_H
#define CCNET_PEER_H

#include <glib.h>
#include <glib-object.h>
#include <stdint.h>


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

enum {
    BIND_UNKNOWN,
    BIND_YES,
    BIND_NO
};

typedef struct _CcnetPeer CcnetPeer;
typedef struct _CcnetPeerClass CcnetPeerClass;

#define CCNET_PEERID_LEN  40


struct _CcnetPeer
{
    GObject       parent_instance;
    char          id[41];
    char          user_id[41];

    gint64        timestamp;

    char         *name;

    unsigned int  is_self : 1;
    unsigned int  can_connect : 1;
    unsigned int  in_local_network : 1;
    unsigned int  in_connection : 1;
    unsigned int  is_ready : 1;
    unsigned int  encrypt_channel : 1;

    gboolean      login_started;
    char          *login_error;
    gboolean      logout_started;


    char         *public_addr;
    uint16_t      public_port;
    char         *service_url;        /* http server for relay in seaflie */

    char         *addr_str;
    uint16_t      port;

    int           net_state;

    GList        *role_list;

    GList        *myrole_list; /* my role on this user */

    gint8         bind_status;
    char         *bind_email;
    char         *session_key;
};

struct _CcnetPeerClass
{
    GObjectClass    parent_class;
};


GType ccnet_peer_get_type (void);


CcnetPeer* ccnet_peer_new (const char *id);


#endif
