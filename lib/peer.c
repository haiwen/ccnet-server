/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "include.h"
#include "peer.h"
#include "ccnet-client.h"
#include "peer-common.h"

static void ccnet_peer_free (GObject *object);


static void
set_property (GObject *object, guint property_id, 
              const GValue *v, GParamSpec *pspec)
{
    set_property_common (object, property_id, v, pspec);
}

static void
ccnet_peer_class_init (CcnetPeerClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

    gobject_class->set_property = set_property;
    gobject_class->get_property = get_property;
    gobject_class->finalize = ccnet_peer_free;

    define_properties (gobject_class);
}

static void
ccnet_peer_init (CcnetPeer *peer)
{
}


CcnetPeer*
ccnet_peer_new (const char *id)
{
    CcnetPeer *peer;

    peer = g_object_new (CCNET_TYPE_PEER, NULL);
    memcpy (peer->id, id, 40);
    peer->id[40] = '\0';

    peer->net_state = PEER_DOWN;
    peer->public_port = 0;
    peer->port = 0;
    return peer;
}

void
ccnet_peer_free (GObject *object)
{
    CcnetPeer *peer = CCNET_PEER (object);
    GList *ptr;

    g_free (peer->name);
    g_free (peer->addr_str);
    g_free (peer->service_url);
    g_free (peer->public_addr);
    g_free (peer->login_error);
    g_free (peer->bind_email);
    g_free (peer->session_key);
    for (ptr = peer->role_list; ptr; ptr = ptr->next)
        g_free (ptr->data);
    g_list_free (peer->role_list);

    for (ptr = peer->myrole_list; ptr; ptr = ptr->next)
        g_free (ptr->data);
    g_list_free (peer->myrole_list);

    G_OBJECT_CLASS(ccnet_peer_parent_class)->finalize (object);
}

