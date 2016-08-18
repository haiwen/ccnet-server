/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "peer.h"
#include "service-stub-proc.h"
#include "service-proxy-proc.h"

#define DEBUG_FLAG CCNET_DEBUG_OTHER
#include "log.h"

typedef struct {
    CcnetServiceProxyProc *proxy_proc;
} ServiceStubPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_SERVICE_STUB_PROC, ServiceStubPriv))

static int service_stub_start (CcnetProcessor *processor, int argc, char **argv);

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

G_DEFINE_TYPE (CcnetServiceStubProc, ccnet_service_stub_proc, CCNET_TYPE_PROCESSOR)


static void
ccnet_service_stub_proc_class_init (CcnetServiceStubProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);
    /* GObjectClass *object_class = G_OBJECT_CLASS (klass); */

    proc_class->name = "service-stub-proc";
    proc_class->start = service_stub_start;
    proc_class->handle_update = handle_update;
    proc_class->handle_response = handle_response;

    g_type_class_add_private (klass, sizeof (ServiceStubPriv));
}

static void
ccnet_service_stub_proc_init (CcnetServiceStubProc *processor)
{
}

static void
strnjoin (int n, char **strs, GString *buf)
{
    int i;

    if (n == 0)
        return;

    g_string_append (buf, strs[0]);

    for (i = 1; i < n; i++) {
        g_string_append (buf, " ");
        g_string_append (buf, strs[i]);
    }
}

static int
service_stub_start (CcnetProcessor *processor, int argc, char **argv)
{
    GString *buf;
    ServiceStubPriv *priv = GET_PRIV (processor);

    g_return_val_if_fail (priv->proxy_proc != NULL, -1);
    buf = g_string_new (NULL);

    CcnetProcessor *pproc = (CcnetProcessor *)priv->proxy_proc;
    if (!pproc->peer->is_local) {
        /* remote? (this may be wrong) */
        g_string_append (buf, "remote ");
        g_string_append (buf, pproc->peer->id);
        g_string_append (buf, " ");
    }

    strnjoin (argc, argv, buf);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

void
ccnet_service_stub_proc_set_proxy_proc (CcnetServiceStubProc *proc,
                                        CcnetProcessor *proxy_proc)
{
    ServiceStubPriv *priv = GET_PRIV (proc);

    priv->proxy_proc = (CcnetServiceProxyProc *)proxy_proc;
}

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    ServiceStubPriv *priv = GET_PRIV (processor);

    /* ccnet_debug ("[Svc Stub] %d handle response: %s %s\n", */
    /*              PRINT_ID(processor->id), code, code_msg); */
    ccnet_processor_handle_response ((CcnetProcessor *)priv->proxy_proc,
                                     code, code_msg, content, clen);
}


static
void handle_update (CcnetProcessor *processor,
                    char *code, char *code_msg,
                    char *content, int clen)
{

    /* ccnet_debug ("[Svc Stub] %d handle update: %s %s\n", */
    /*              PRINT_ID(processor->id), code, code_msg); */
    ccnet_processor_send_update (processor, code, code_msg, content, clen);
}
