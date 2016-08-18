/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "include.h"

#include "ccnet-client.h"

#include "peer.h"
#include "processor.h"
#include "invoke-service-proc.h"

static int invoke_service_start (CcnetProcessor *processor, 
                                  int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);


#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_SERVICE_PROC, CcnetServiceProcPriv))

G_DEFINE_TYPE (CcnetServiceProc, ccnet_service_proc, CCNET_TYPE_PROCESSOR)

static void
ccnet_service_proc_class_init (CcnetServiceProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = invoke_service_start;
    proc_class->handle_response = handle_response;
}

static void
ccnet_service_proc_init (CcnetServiceProc *processor)
{
    /* CCNET_PROCESSOR (processor)->state = INIT; */
}

static int invoke_service_start (CcnetProcessor *processor, 
                                 int argc, char **argv)
{
    char *cmd;

    if (argc == 0) {
        g_warning ("Invalid argument for service-proc\n");
        ccnet_processor_done (processor, FALSE);
    }
    
    cmd = ccnet_util_strjoin_n (" ", argc, argv);

    ccnet_client_send_request (processor->session,
                               REQUEST_ID (processor->id), cmd);

    return 0;
}

void
ccnet_service_proc_set_response_cb (CcnetServiceProc *proc,
                                    ResponseCB resp_cb, void *data)
{
    proc->resp_cb = resp_cb;
    proc->cb_data = data;
}


static void handle_response (CcnetProcessor *processor, 
                             char *code, char *code_msg,
                             char *content, int clen)
{
    CcnetServiceProc *proc = (CcnetServiceProc *) processor;

    if (proc->resp_cb)
        proc->resp_cb (code, code_msg, content, clen, proc->cb_data);

    if (code[0] == '4' || code[0] == '5')
        ccnet_processor_done (processor, FALSE);
}
