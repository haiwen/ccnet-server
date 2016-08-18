/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"


#include "sample-slave-proc.h"

#include "peer.h"
#include "session.h"

#define DEBUG_FLAG CCNET_DEBUG_PROCESSOR
#include "log.h"

enum {
    INIT
};

typedef struct  {
    int   rate;
} CcnetSampleSlaveProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_SAMPLE_SLAVE_PROC, CcnetSampleSlaveProcPriv))


G_DEFINE_TYPE (CcnetSampleSlaveProc, ccnet_sample_slave_proc, CCNET_TYPE_PROCESSOR)

static int sample_slave_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

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


    /* should always chain up */
    CCNET_PROCESSOR_CLASS(ccnet_sample_slave_proc_parent_class)->release_resource (gobject);
}

static void shutdown (CcnetProcessor *processor)
{
    /* The processor is shutdown abnormally. */

    /* the release_resource() will be called after calling shutdown(),
     * so only do things that release_resource() does not do. */

    /* Do not chain up here. */
}

static void
ccnet_sample_slave_proc_class_init (CcnetSampleSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

    proc_class->name = "sample-slave-proc";
    proc_class->start = sample_slave_start;
    proc_class->handle_update = handle_update;
    proc_class->shutdown = shutdown;
    gobject_class->finalize = sample_slave_finalize;

    g_type_class_add_private (klass, sizeof(CcnetSampleSlaveProcPriv));
}

static void
ccnet_sample_slave_proc_init (CcnetSampleSlaveProc *processor)
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
}




static void shutdown (CcnetProcessor *processor)
{
    /* The processor is shutdown abnormally. */

    /* the release_resource() will be called after calling shutdown(),
     * so only do things that release_resource() does not do. */

    /* Do not chain up here. */
}


static int sample_slave_start (CcnetProcessor *processor, int argc, char **argv)
{
    CcnetSampleSlaveProcPriv *priv = GET_PRIV (processor);
    priv->rate = DEFAULT_RATE;
    processor->state = INIT;
    
    ccnet_processor_send_response (processor, "200", "OK", "sample response",
                                   strlen("sample response") + 1);

    return 0;
}

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    if (memcpy(code, "200", 3) == 0) {
        ccnet_processor_done (processor, TRUE);
    } else {
        /* code and code_msg are ended with '\0' */
        ccnet_warning ("Bad update from peer %s(%.8s), %s:%s\n", 
                       processor->peer->name, processor->peer->id,
                       code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}
