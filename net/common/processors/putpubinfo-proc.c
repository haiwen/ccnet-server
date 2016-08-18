/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "peer.h"
#include "session.h"
#include "putpubinfo-proc.h"


#define DEBUG_FLAG CCNET_DEBUG_CONNECTION
#include "log.h"



static int put_pubinfo_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);


G_DEFINE_TYPE (CcnetPutpubinfoProc, ccnet_putpubinfo_proc, CCNET_TYPE_PROCESSOR)


static void
ccnet_putpubinfo_proc_class_init (CcnetPutpubinfoProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);
    /* GObjectClass *gobject_class = G_OBJECT_CLASS (klass); */

    proc_class->name = "putpubinfo-proc";
    proc_class->start = put_pubinfo_start;
    proc_class->handle_update = handle_update;
}

static void
ccnet_putpubinfo_proc_init (CcnetPutpubinfoProc *processor)
{
}


static void put_pubinfo (CcnetProcessor *processor)
{
    GString *str = ccnet_peer_to_string (processor->session->myself);

    ccnet_processor_send_response (processor, "200", "OK",
                                   str->str, str->len+1);
    ccnet_processor_done (processor, TRUE);

    g_string_free (str, TRUE);
}


static int put_pubinfo_start (CcnetProcessor *processor, int argc, char **argv)
{
    put_pubinfo (processor);
    return 0;
}


static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    return;
}
