/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "include.h"
#include "processor.h"
#include "ccnet-client.h"

#include "peer.h"
#include "proc-factory.h"

typedef struct {
    GHashTable *proc_type_table;
} CcnetProcFactoryPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_PROC_FACTORY, CcnetProcFactoryPriv))

G_DEFINE_TYPE (CcnetProcFactory, ccnet_proc_factory, G_TYPE_OBJECT)

static void
ccnet_proc_factory_free (GObject *factory);

static void
ccnet_proc_factory_class_init (CcnetProcFactoryClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

    gobject_class->finalize = ccnet_proc_factory_free;

    g_type_class_add_private (klass, sizeof (CcnetProcFactoryPriv));
}

static void
ccnet_proc_factory_init (CcnetProcFactory *factory)
{
    CcnetProcFactoryPriv *priv = GET_PRIV (factory);

    priv->proc_type_table = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                   g_free, NULL);
}

static void
ccnet_proc_factory_free (GObject *factory)
{
    CcnetProcFactoryPriv *priv = GET_PRIV (factory);

    g_hash_table_destroy (priv->proc_type_table);
}

void
ccnet_proc_factory_register_processor (CcnetProcFactory *factory,
                                       const char *serv_name,
                                       GType proc_type)
{
    CcnetProcFactoryPriv *priv = GET_PRIV (factory);

    CcnetProcessorClass *proc_class = 
        (CcnetProcessorClass *)g_type_class_ref(proc_type);
    g_type_class_unref (proc_class);

    /* check dumplication */
    if (g_hash_table_lookup(priv->proc_type_table, serv_name))
        return;

    g_hash_table_insert (priv->proc_type_table, g_strdup (serv_name), 
                         (gpointer) proc_type);
}

GType ccnet_sendcmd_proc_get_type ();
GType ccnet_mqclient_proc_get_type ();
GType ccnet_async_rpc_proc_get_type ();

CcnetProcFactory *ccnet_proc_factory_new (CcnetClient *session)
{
    CcnetProcFactory *factory;

    factory = g_object_new (CCNET_TYPE_PROC_FACTORY, NULL);
    factory->session = session;

    /* register fundamental processors */

    ccnet_proc_factory_register_processor (factory, "send-cmd",
                                           ccnet_sendcmd_proc_get_type ());
    /* ccnet_proc_factory_register_processor (factory, "send-event", */
    /*                                        ccnet_sendevent_proc_get_type ()); */
    ccnet_proc_factory_register_processor (factory, "mq-client",
                                           ccnet_mqclient_proc_get_type ());

    ccnet_proc_factory_register_processor (factory, "async-rpc",
                                           ccnet_async_rpc_proc_get_type ());

    return factory;
}

static GType ccnet_proc_factory_get_proc_type (CcnetProcFactory *factory,
                                               const char *serv_name)
{
    CcnetProcFactoryPriv *priv = GET_PRIV (factory);

    return (GType) g_hash_table_lookup (priv->proc_type_table, serv_name);
}

CcnetProcessor *
ccnet_proc_factory_create_processor (CcnetProcFactory *factory,
                                     const char *serv_name,
                                     int is_master,
                                     int req_id)
{
    GType type;
    CcnetProcessor *processor;

    type = ccnet_proc_factory_get_proc_type (factory, serv_name);
    if (type == 0) {
        g_warning ("No processor for service: %s.\n", serv_name);
        return NULL;
    }

    processor = g_object_new (type, NULL);
    processor->session = factory->session;
    if (is_master) {
        if (req_id == 0)
            processor->id = MASTER_ID (
                ccnet_client_get_request_id (factory->session));
        else
            processor->id = MASTER_ID (req_id);
    } else
        processor->id = SLAVE_ID (req_id);

    /* Set the service this processor provide.
     * This may be different from the processor class name.
     */
    processor->name = g_strdup(serv_name);

    ccnet_client_add_processor (factory->session, processor);

    return processor;
}


CcnetProcessor *
ccnet_proc_factory_create_master_processor (CcnetProcFactory *factory,
                                            const char *serv_name)
{
    return ccnet_proc_factory_create_processor (factory, serv_name,
                                                MASTER, 0);
}

CcnetProcessor *
ccnet_proc_factory_create_remote_master_processor (CcnetProcFactory *factory,
                                                   const char *serv_name,
                                                   const char *peer_id)
{
    GType type;
    CcnetProcessor *processor;

    type = ccnet_proc_factory_get_proc_type (factory, serv_name);
    if (type == 0) {
        ccnet_warning ("No such processor type: %s.\n", serv_name);
        return NULL;
    }


    processor = g_object_new (type, NULL);
    processor->peer_id = g_strdup(peer_id);
    processor->session = factory->session;
    processor->id = MASTER_ID (ccnet_client_get_request_id (factory->session));

    /* Set the real processor name.
     * This may be different from the processor class name.
     */
    processor->name = g_strdup(serv_name);

    ccnet_client_add_processor (factory->session, processor);

    return processor;
}


CcnetProcessor *
ccnet_proc_factory_create_slave_processor (CcnetProcFactory *factory,
                                           const char *serv_name,
                                           const char *peer_id,
                                           int req_id)
{
    GType type;
    CcnetProcessor *processor;

    type = ccnet_proc_factory_get_proc_type (factory, serv_name);
    if (type == 0) {
        g_warning ("No such processor type: %s.\n", serv_name);
        return NULL;
    }

    processor = g_object_new (type, NULL);
    processor->peer_id = g_strdup(peer_id);
    processor->session = factory->session;
    processor->id = SLAVE_ID (req_id);

    /* Set the real processor name.
     * This may be different from the processor class name.
     */
    processor->name = g_strdup(serv_name);

    ccnet_client_add_processor (factory->session, processor);

    return processor;
}


void
ccnet_proc_factory_recycle (CcnetProcFactory *factory,
                            CcnetProcessor *processor)
{
    ccnet_client_remove_processor (factory->session, processor);
    g_object_unref (processor);
}
