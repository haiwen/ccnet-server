/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "peer.h"
#include "session.h"

#include "echo-proc.h"

#define DEBUG_FLAG CCNET_DEBUG_PROCESSOR
#include "log.h"


#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_ECHO_PROC, CcnetEchoProcPriv))

G_DEFINE_TYPE (CcnetEchoProc, ccnet_echo_proc, CCNET_TYPE_PROCESSOR);


static int echo_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* should always chain up */
    CCNET_PROCESSOR_CLASS(ccnet_echo_proc_parent_class)->release_resource (processor);
}

static void echo_shutdown (CcnetProcessor *processor)
{
    /* The processor is shutdown. */

    /* the release_resource() will be called after calling shutdown(),
     * so only do things that release_resource() does not do. */

    /* Do not chain up here. */
}

static void
ccnet_echo_proc_class_init (CcnetEchoProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "echo-proc";
    proc_class->start = echo_start;
    proc_class->handle_response = handle_response;
    proc_class->shutdown = echo_shutdown;
    proc_class->release_resource = release_resource;
}

static void
ccnet_echo_proc_init (CcnetEchoProc *processor)
{
}

static int
echo_start (CcnetProcessor *processor, int argc, char **argv)
{
    if (IS_SLAVE(processor)) {
        char buf[256];
        int len;
        len = sprintf (buf, "%s %s", processor->session->base.name,
                       processor->session->base.id);
        ccnet_processor_send_response (processor, 
                                       "300", "", buf, len + 1);
        return 0;
    }

    ccnet_processor_send_request (processor, "echo");
    return 0;
}


static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    if (memcmp(code, "300", 3) == 0) {
        if (content[clen-1] != '\0') {
            ccnet_processor_done (processor, FALSE);
            return;
        }
        fprintf (stderr, "Receive echo response: %s\n", content);
        ccnet_processor_done (processor, TRUE);
    } else {
        /* code and code_msg are ended with '\0' */
        ccnet_warning ("Bad response from peer %s(%.8s), %s:%s\n", 
                       processor->peer->name, processor->peer->id,
                       code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}

