/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_SERVICE_PROC_H
#define CCNET_SERVICE_PROC_H

#include <glib-object.h>
#include "processor.h"

#define CCNET_TYPE_SERVICE_PROC                  (ccnet_service_proc_get_type ())
#define CCNET_SERVICE_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SERVICE_PROC, CcnetServiceProc))
#define CCNET_IS_SERVICE_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SERVICE_PROC))
#define CCNET_SERVICE_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SERVICE_PROC, CcnetServiceProcClass))
#define CCNET_IS_SERVICE_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SERVICE_PROC))
#define CCNET_SERVICE_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SERVICE_PROC, CcnetServiceProcClass))

typedef struct _CcnetServiceProc CcnetServiceProc;
typedef struct _CcnetServiceProcClass CcnetServiceProcClass;

typedef void (*ResponseCB) (const char *code, const char *code_msg,
                            char *content, int clen, void *cb_data);

struct _CcnetServiceProc {
    CcnetProcessor parent_instance;

    ResponseCB     resp_cb;
    void          *cb_data;
};

struct _CcnetServiceProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_service_proc_get_type ();

void ccnet_service_proc_set_response_cb (CcnetServiceProc *proc,
                                         ResponseCB resp_cb, void *data);


#endif
