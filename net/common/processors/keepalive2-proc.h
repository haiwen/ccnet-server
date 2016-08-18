/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_KEEPALIVE2_PROC_H
#define CCNET_KEEPALIVE2_PROC_H

#include <glib-object.h>
#include "processor.h"

#define CCNET_TYPE_KEEPALIVE2_PROC                  (ccnet_keepalive2_proc_get_type ())
#define CCNET_KEEPALIVE2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_KEEPALIVE2_PROC, CcnetKeepalive2Proc))
#define CCNET_IS_KEEPALIVE2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_KEEPALIVE2_PROC))
#define CCNET_KEEPALIVE2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_KEEPALIVE2_PROC, CcnetKeepalive2ProcClass))
#define CCNET_IS_KEEPALIVE2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_KEEPALIVE2_PROC))
#define CCNET_KEEPALIVE2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_KEEPALIVE2_PROC, CcnetKeepalive2ProcClass))

typedef struct _CcnetKeepalive2Proc CcnetKeepalive2Proc;
typedef struct _CcnetKeepalive2ProcClass CcnetKeepalive2ProcClass;

struct _CcnetKeepalive2Proc {
    CcnetProcessor parent_instance;
};

struct _CcnetKeepalive2ProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_keepalive2_proc_get_type ();

#endif
