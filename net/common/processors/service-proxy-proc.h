/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_SERVICE_PROXY_PROC_H
#define CCNET_SERVICE_PROXY_PROC_H

#include <glib-object.h>

#include "processor.h"

#define CCNET_TYPE_SERVICE_PROXY_PROC                  (ccnet_service_proxy_proc_get_type ())
#define CCNET_SERVICE_PROXY_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SERVICE_PROXY_PROC, CcnetServiceProxyProc))
#define CCNET_IS_SERVICE_PROXY_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SERVICE_PROXY_PROC))
#define CCNET_SERVICE_PROXY_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SERVICE_PROXY_PROC, CcnetServiceProxyProcClass))
#define CCNET_IS_SERVICE_PROXY_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SERVICE_PROXY_PROC))
#define CCNET_SERVICE_PROXY_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SERVICE_PROXY_PROC, CcnetServiceProxyProcClass))

typedef struct _CcnetServiceProxyProc CcnetServiceProxyProc;
typedef struct _CcnetServiceProxyProcClass CcnetServiceProxyProcClass;

struct _CcnetServiceProxyProc {
    CcnetProcessor parent_instance;
};

struct _CcnetServiceProxyProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_service_proxy_proc_get_type ();

void ccnet_service_proxy_invoke_remote (CcnetProcessor *processor,
                                        CcnetPeer *remote,
                                        int argc, char **argv);

void ccnet_service_proxy_invoke_local (CcnetProcessor *processor,
                                       CcnetPeer *local,
                                       int argc, char **argv);

#endif
