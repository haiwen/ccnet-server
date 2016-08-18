/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "timer.h"
#include "peer.h"
#include "session.h"

#include "sample-master-proc.h"

#define DEBUG_FLAG CCNET_DEBUG_PROCESSOR
#include "log.h"

enum {
    INIT,
    REQUEST_SEND,
    CONNECTED,
};


typedef struct  {
    GHashTable   *registered;
    int           rate;
} CcnetSampleProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_SAMPLE_PROC, CcnetSampleProcPriv))

G_DEFINE_TYPE (CcnetSampleProc, ccnet_sample_proc, CCNET_TYPE_PROCESSOR);


static int sample_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);
static void disconnect_signals (CcnetProcessor *processor)
{
}

static void
set_property (GObject *object, guint property_id, 
              const GValue *v, GParamSpec *pspec)
{
    CcnetSampleProcPriv *priv = GET_PRIV(object);

    switch (property_id) {
    case P_RATE:
        priv->rate = g_value_get_int (v);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
get_property (GObject *object, guint property_id,
              GValue *v, GParamSpec *pspec)
{
    CcnetSampleProcPriv *priv = GET_PRIV(object);

    switch (property_id) {
    case P_RATE: 
        g_value_set_int (v, priv->rate);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
release_resource(CcnetProcessor *processor)
{
    /* Release the resource hold by this processor here.
     *
     * It will always be called either when the processor is shutdown
     * abnormally (via call ccnet_processor_shutdown()), 
     * or when it finishes its task normally (via call ccnet_processor_done()).
     *
     * Note, you must release `all the timers' and `disconnect all the signals'.
     * The `retry_timer' will be freed by the default_release_resource() 
     * in chain up.
     */

    CcnetSampleProcPriv *priv = GET_PRIV (processor);

    /* clean the items in hash table, but do not unref the hash table self. */
    g_hash_table_remove_all (priv->registered);

    /* if your processor connected any signals, disconnect it here */
    disconnect_signals (processor);

    /* should always chain up */
    CCNET_PROCESSOR_CLASS(ccnet_sample_proc_parent_class)->release_resource (processor);
}

static void shutdown (CcnetProcessor *processor)
{
    /* The processor is shutdown abnormally. */

    /* the release_resource() will be called after calling shutdown(),
     * so only do things that release_resource() does not do. */

    /* Do not chain up here. */
}

static void finalize (GObject *gobject);

static void
ccnet_sample_proc_class_init (CcnetSampleProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

    proc_class->name = "sample-master-proc";
    proc_class->start = sample_start;
    proc_class->handle_response = handle_response;
    proc_class->shutdown = shutdown;
    proc_class->release_resource = release_resource;

    gobject_class->set_property = set_property;
    gobject_class->get_property = get_property;
    gobject_class->finalize = finalize;

    g_object_class_install_property (gobject_class, P_RATE,
        g_param_spec_int ( "rate", NULL, "Transfer Rate",
                          0, INT_MAX, 0, G_PARAM_READWRITE));
    
    g_type_class_add_private (klass, sizeof (CcnetSendfileProcPriv));
}

static void
ccnet_sample_proc_init (CcnetSampleProc *processor)
{
    /*
     * The processor used be used multi-times for different peers.
     * And this function will only be called once.
     *
     * So only initialize things that will be used cross sessions.
     *
     * Normally, use start() for initialization, and use release_resouce()
     * for finalization.
     */

    CcnetSampleProcPriv *priv = GET_PRIV (processor);
    priv->registered = g_hash_table_new (g_direct_hash, g_direct_equal);
}

static void finalize (GObject *gobject)
{
    /* undo the things init() do */

    CcnetSampleProcPriv *priv = GET_PRIV (processor);

    g_hash_table_unref (priv->registered);

    G_OBJECT_CLASS (ccnet_sample_proc_parent_class)->finalize (gobject);
}



static int timeout_cb(CcnetProcessor *processor)
{
    ccnet_warning ("sample slave does not reponse to us\n");
    ccnet_processor_done (processor, FALSE);

    /* return FALSE to cancel the timer */
    return FALSE;
}

static int
sample_start (CcnetProcessor *processor, int argc, char **argv)
{
    CcnetSampleProcPriv *priv = GET_PRIV (processor);

    /* initialization here */
    priv->rate = DEFAULT_RATE;
    processor->state = INIT;

    /* send request */
    ccnet_processor_send_request (processor, "sample-slave");

    processor->state = REQUEST_SENT;

    /* for convenient, the processor provide a retry_timer, you can
     * use it for other purpose. This timer will be freed automatically
     * in the default_shutdown() of CcnetProcessor base class.
     *
     * So if you override the default_shutdown(), you should
     * free the timer yourself.
     */
    processor->retry_timer = ccnet_timer_new ((TimerCB)timeout_cb, processor,
                                              10 * 1000);


    return 0;
}


static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    if (memcpy(code, "200", 3) == 0) {
        ccnet_processor_send_update (processor, "200", "OK", "sample update",
                                     strlen("sample update") + 1);
        ccnet_processor_done (processor, TRUE);
    } else {
        /* code and code_msg are ended with '\0' */
        ccnet_warning ("Bad response from peer %s(%.8s), %s:%s\n", 
                       processor->peer->name, processor->peer->id,
                       code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}

