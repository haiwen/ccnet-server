/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "ccnet-db.h"
#include "timer.h"

#include "peer.h"
#include "session.h"
#include "processors/mqserver-proc.h"

#include "message.h"
#include "message-manager.h"
#include "peer-mgr.h"

#define DEBUG_FLAG CCNET_DEBUG_MESSAGE
#include "log.h"


struct MessageManagerPriv {
    GHashTable *subscribers;

#ifdef CCNET_SERVER
    
#endif
};

#define GET_PRIV(o)  \
(G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_MESSAGE_MANAGER, MessageManagerPriv))

G_DEFINE_TYPE (CcnetMessageManager, ccnet_message_manager, G_TYPE_OBJECT);


static void
ccnet_message_manager_class_init (CcnetMessageManagerClass *class)
{
    /* GObjectClass *object_class; */

    g_type_class_add_private (class, sizeof (MessageManagerPriv));
}

static void
ccnet_message_manager_init (CcnetMessageManager *manager)
{
    manager->priv = GET_PRIV(manager);
}

CcnetMessageManager *
ccnet_message_manager_new (CcnetSession *session)
{
    CcnetMessageManager *manager;

    manager = g_object_new (CCNET_TYPE_MESSAGE_MANAGER, NULL);
    manager->session = session;

    manager->priv->subscribers = g_hash_table_new_full (
        g_str_hash, g_str_equal, g_free, NULL);

    return manager;
}

int
ccnet_message_manager_start (CcnetMessageManager *manager)
{
    return 0;
}

static gboolean 
handle_inner_message (CcnetMessageManager *manager,
                      CcnetMessage *msg)
{
    if (strcmp(msg->app, IPEERMGR_APP) == 0) {
        ccnet_peer_manager_receive_message (manager->session->peer_mgr, msg);
        return TRUE;
    }

    return FALSE;
}

int 
ccnet_message_manager_add_msg(CcnetMessageManager *manager,
                              CcnetMessage *msg,
                              int msg_type)
{
    MessageManagerPriv *priv = manager->priv;
    GList *app_subscribers, *ptr;
    CcnetProcessor *processor;

    switch (msg_type) {
    case MSG_TYPE_RECV:
        if (handle_inner_message(manager, msg))
            break;

        app_subscribers = g_hash_table_lookup (priv->subscribers,
                                               msg->app);
        if (!app_subscribers)
            break;

        ptr = app_subscribers;
        while (ptr) {
            processor = ptr->data;
            ccnet_mqserver_proc_put_message (processor, msg);
            ptr = ptr->next;
        }
        break;
    case MSG_TYPE_SYS:
        app_subscribers = g_hash_table_lookup (priv->subscribers, msg->app);
        if (!app_subscribers)
            break;

        ptr = app_subscribers;
        while (ptr) {
            processor = ptr->data;
            ccnet_mqserver_proc_put_message (processor, msg);
            ptr = ptr->next;
        }
        break;
    }

    return 0;
}

int
ccnet_message_manager_subscribe_app (CcnetMessageManager *manager,
                                     CcnetProcessor *mq_proc,
                                     int n_app, char **apps)
{
    MessageManagerPriv *priv = manager->priv;
    GList *app_subscribers;
    int i;

    for (i = 0; i < n_app; ++i) {
        ccnet_debug ("[Msg] subscribe app %s\n", apps[i]);

        app_subscribers = g_hash_table_lookup (priv->subscribers, apps[i]);
        app_subscribers = g_list_prepend (app_subscribers, mq_proc);
        g_hash_table_replace (priv->subscribers, g_strdup (apps[i]),
                              app_subscribers);
    }

    return 0;
}

int
ccnet_message_manager_unsubscribe_app (CcnetMessageManager *manager,
                                       CcnetProcessor *mq_proc,
                                       int n_app, char **apps)
{
    MessageManagerPriv *priv = manager->priv;
    GList *app_subscribers;
    int i;
    int ret = 0; 

    for (i = 0; i < n_app; ++i) {
        app_subscribers = g_hash_table_lookup (priv->subscribers, apps[i]);
        if (!app_subscribers) {
            ccnet_warning ("cannot unsubscribe from app %s, "
                           "no such app subscribed.\n", apps[i]);
            ret = -1;
            continue;
        }

        ccnet_debug ("[Msg] unsubscribe app %s\n", apps[i]);

        app_subscribers = g_list_remove (app_subscribers, mq_proc);

        if (app_subscribers)
            g_hash_table_replace (priv->subscribers, g_strdup (apps[i]),
                                  app_subscribers);
        else
            g_hash_table_remove (priv->subscribers, apps[i]);
    }

    return ret;
}
