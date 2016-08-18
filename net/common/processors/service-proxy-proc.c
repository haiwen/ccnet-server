/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "session.h"
#include "peer.h"
#include "peer-mgr.h"
#include "proc-factory.h"
#include "service-proxy-proc.h"
#include "service-stub-proc.h"

#define DEBUG_FLAG CCNET_DEBUG_PROCESSOR
#include "log.h"

#define SC_BAD_CMD_FMT "400"
#define SS_BAD_CMD_FMT "Bad command format"



typedef struct {
    CcnetServiceStubProc *stub_proc;
    char *name;
} ServiceProxyPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_SERVICE_PROXY_PROC, ServiceProxyPriv))

static int service_proxy_start (CcnetProcessor *processor, int argc, char **argv);

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

/* called by stub processor */
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

G_DEFINE_TYPE (CcnetServiceProxyProc, ccnet_service_proxy_proc, CCNET_TYPE_PROCESSOR)

static void
release_resource(CcnetProcessor *processor)
{
    ServiceProxyPriv *priv = GET_PRIV(processor);
    if (priv->name) {
        g_free (priv->name);
        priv->name = NULL;
    }

    /* should always chain up */
    CCNET_PROCESSOR_CLASS(ccnet_service_proxy_proc_parent_class)->release_resource (processor);
}

static void
ccnet_service_proxy_proc_class_init (CcnetServiceProxyProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);
    /* GObjectClass *object_class = G_OBJECT_CLASS (klass); */

    proc_class->name = "service-proxy-proc";
    proc_class->start = service_proxy_start;
    proc_class->handle_update = handle_update;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (ServiceProxyPriv));
}

static void
ccnet_service_proxy_proc_init (CcnetServiceProxyProc *processor)
{
    ServiceProxyPriv *priv = GET_PRIV(processor);
    priv->name = NULL;
}

static int
service_proxy_start (CcnetProcessor *processor, int argc, char **argv)
{
    return 0;
}


static char* proc_name_strjoin_n (const char *seperator, int argc, char **argv)
{
    GString *buf;
    int i;
    char *str;

    buf = g_string_new (argv[0]);
    for (i = 1; i < argc; ++i) {
        g_string_append (buf, seperator);
        g_string_append (buf, argv[i]);
    }
    str = buf->str;
    g_string_free (buf, FALSE);
    return str;
}

void
ccnet_service_proxy_invoke_remote (CcnetProcessor *processor,
                                   CcnetPeer *remote,
                                   int argc, char **argv)
{
    CcnetServiceStubProc *stub_proc;
    ServiceProxyPriv *priv = GET_PRIV(processor);

    if (argc < 1) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    
    priv->name = proc_name_strjoin_n(" ", argc, argv);

    stub_proc = CCNET_SERVICE_STUB_PROC (
        ccnet_proc_factory_create_master_processor (
            processor->session->proc_factory, "service-stub", remote)
        );
    priv->stub_proc = stub_proc;
    ccnet_service_stub_proc_set_proxy_proc (stub_proc, processor);

    /* Start can fail if the remote end is not connected. */
    if (ccnet_processor_start (CCNET_PROCESSOR(stub_proc), argc, argv) < 0) {
        ccnet_processor_send_response (processor, SC_PROC_DEAD, SS_PROC_DEAD,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }
}

/* TODO: the same as above, can use one function instead */
void
ccnet_service_proxy_invoke_local (CcnetProcessor *processor,
                                  CcnetPeer *local,
                                  int argc, char **argv)
{
    CcnetServiceStubProc *stub_proc;
    ServiceProxyPriv *priv = GET_PRIV(processor);
    
    if (argc < 1) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    priv->name = proc_name_strjoin_n(" ", argc, argv);

    stub_proc = CCNET_SERVICE_STUB_PROC (
        ccnet_proc_factory_create_master_processor (
            processor->session->proc_factory, "service-stub", local)
        );
    priv->stub_proc = stub_proc;
    ccnet_service_stub_proc_set_proxy_proc (stub_proc, processor);

    ccnet_processor_start (CCNET_PROCESSOR(stub_proc), argc, argv);
}

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    ServiceProxyPriv *priv = GET_PRIV (processor);
    if(!priv->stub_proc || !((CcnetProcessor *)priv->stub_proc)->peer->is_local)
        ccnet_debug ("[Svc Proxy] %s:%d [%s] handle update: %s %s\n",
                     GET_PNAME(processor), PRINT_ID(processor->id),
                     priv->name, code, code_msg);

    ccnet_processor_handle_update ((CcnetProcessor *)priv->stub_proc,
                                   code, code_msg, content, clen);
}


static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    ServiceProxyPriv *priv = GET_PRIV (processor);
    if(!priv->stub_proc || !((CcnetProcessor *)priv->stub_proc)->peer->is_local)
        ccnet_debug ("[Svc Proxy] %s:%d [%s] handle response: %s %s\n",
                     GET_PNAME(processor), PRINT_ID(processor->id),
                     priv->name, code, code_msg);

    /* relay this response */
    ccnet_processor_send_response (processor, code, code_msg, content, clen);
}
