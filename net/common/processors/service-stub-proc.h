/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_SERVICE_STUB_PROC_H
#define CCNET_SERVICE_STUB_PROC_H

#include <glib-object.h>

#include "processor.h"


#define CCNET_TYPE_SERVICE_STUB_PROC                  (ccnet_service_stub_proc_get_type ())
#define CCNET_SERVICE_STUB_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SERVICE_STUB_PROC, CcnetServiceStubProc))
#define CCNET_IS_SERVICE_STUB_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SERVICE_STUB_PROC))
#define CCNET_SERVICE_STUB_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SERVICE_STUB_PROC, CcnetServiceStubProcClass))
#define CCNET_IS_SERVICE_STUB_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SERVICE_STUB_PROC))
#define CCNET_SERVICE_STUB_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SERVICE_STUB_PROC, CcnetServiceStubProcClass))

typedef struct _CcnetServiceStubProc CcnetServiceStubProc;
typedef struct _CcnetServiceStubProcClass CcnetServiceStubProcClass;

struct _CcnetServiceStubProc {
    CcnetProcessor parent_instance;


};

struct _CcnetServiceStubProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_service_stub_proc_get_type ();

void ccnet_service_stub_proc_set_proxy_proc (CcnetServiceStubProc *proc,
                                             CcnetProcessor *processor);

void ccnet_service_stub_proc_send_update (CcnetServiceStubProc *proc,
                                          char *code, char *code_msg,
                                          char *content, int clen);

#endif
