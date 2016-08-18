/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_PEER_MGR_H
#define CCNET_PEER_MGR_H

#include <glib.h>
#include <glib-object.h>

#include "peer.h"

#define CCNET_TYPE_PEER_MANAGER                  (ccnet_peer_manager_get_type ())
#define CCNET_PEER_MANAGER(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_PEER_MANAGER, CcnetPeerManager))
#define CCNET_IS_PEER_MANAGER(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_PEER_MANAGER))
#define CCNET_PEER_MANAGER_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_PEER_MANAGER, CcnetPeerManagerClass))
#define CCNET_IS_PEER_MANAGER_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_PEER_MANAGER))
#define CCNET_PEER_MANAGER_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_PEER_MANAGER, CcnetPeerManagerClass))


typedef struct _CcnetPeerManager CcnetPeerManager;
typedef struct _CcnetPeerManagerClass CcnetPeerManagerClass;

typedef struct CcnetPeerManagerPriv CcnetPeerManagerPriv;

struct _CcnetPeerManager
{
    GObject         parent_instance;

    CcnetSession   *session;
    
    char           *peerdb_path;

    GHashTable     *peer_hash;

    GList          *local_peers;

    guint32         connected_peer;   

    CcnetPeerManagerPriv *priv;
};

struct _CcnetPeerManagerClass
{
    GObjectClass    parent_class;
};

GType ccnet_peer_manager_get_type  (void);

CcnetPeerManager* ccnet_peer_manager_new (CcnetSession *);

int
ccnet_peer_manager_prepare (CcnetPeerManager *manager);

void ccnet_peer_manager_free (CcnetPeerManager *manager);

void ccnet_peer_manager_start (CcnetPeerManager *manager);
void ccnet_peer_manager_on_exit (CcnetPeerManager *manager);

void ccnet_peer_manager_add_peer (CcnetPeerManager *manager, CcnetPeer *peer);
void ccnet_peer_manager_remove_peer (CcnetPeerManager *manager, CcnetPeer *peer);

CcnetPeer* ccnet_peer_manager_get_peer (CcnetPeerManager *manager,
                                        const char *peer_id);

CcnetPeer* ccnet_peer_manager_get_peer_by_name (CcnetPeerManager *manager,
                                                const char *name);

GList* ccnet_peer_manager_get_peer_list (CcnetPeerManager *manager);
GList* ccnet_peer_manager_get_peers_with_role (CcnetPeerManager *manager,
                                               const char *role);

void ccnet_peer_manager_add_role (CcnetPeerManager *manager,
                                  CcnetPeer *peer,
                                  const char *role);

void ccnet_peer_manager_remove_role (CcnetPeerManager *manager,
                                     CcnetPeer *peer,
                                     const char *role);

void ccnet_peer_manager_add_local_peer (CcnetPeerManager *manager,
                                        CcnetPeer *peer);
void ccnet_peer_manager_remove_local_peer (CcnetPeerManager *manager,
                                           CcnetPeer *peer);

struct _CcnetMessage;
void ccnet_peer_manager_receive_message (CcnetPeerManager *manager,
                                         struct _CcnetMessage *msg);

void
ccnet_peer_manager_notify_peer_role (CcnetPeerManager *manager,
                                     CcnetPeer *peer);

void
ccnet_peer_manager_set_peer_public_addr (CcnetPeerManager *manager,
                                         CcnetPeer *peer,
                                         const char *addr,
                                         int port);

#ifdef CCNET_SERVER
void
ccnet_peer_manager_send_bind_status (CcnetPeerManager *manager,
                                     const char *peer_id,
                                     const char *result);
#endif /* CCNET_SERVER */

/* function of resolving peer */
CcnetPeer *
ccnet_peer_manager_add_resolve_peer (CcnetPeerManager *manager,
                                     const char *ip_or_domain,
                                     uint16_t port);

GList *
ccnet_peer_manager_get_resolve_peers (CcnetPeerManager *manager);

void
ccnet_peer_manager_redirect_peer (CcnetPeerManager *manager,
                                  CcnetPeer *peer,
                                  CcnetPeer *to);

void
ccnet_peer_manager_send_ready_message (CcnetPeerManager *manager, CcnetPeer *peer);

void
ccnet_peer_manager_on_peer_session_key_sent (CcnetPeerManager *manager,
                                             CcnetPeer *peer);
void
ccnet_peer_manager_on_peer_session_key_received (CcnetPeerManager *manager,
                                                 CcnetPeer *peer);

#endif
