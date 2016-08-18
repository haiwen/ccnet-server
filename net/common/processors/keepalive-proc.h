/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_GETPEERINFO_PROC_H
#define CCNET_GETPEERINFO_PROC_H

#include <glib-object.h>
#include "processor.h"

#define CCNET_TYPE_KEEPALIVE_PROC                  (ccnet_keepalive_proc_get_type ())
#define CCNET_KEEPALIVE_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_KEEPALIVE_PROC, CcnetKeepaliveProc))
#define CCNET_IS_KEEPALIVE_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_KEEPALIVE_PROC))
#define CCNET_KEEPALIVE_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_KEEPALIVE_PROC, CcnetKeepaliveProcClass))
#define CCNET_IS_KEEPALIVE_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_KEEPALIVE_PROC))
#define CCNET_KEEPALIVE_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_KEEPALIVE_PROC, CcnetKeepaliveProcClass))

typedef struct _CcnetKeepaliveProc CcnetKeepaliveProc;
typedef struct _CcnetKeepaliveProcClass CcnetKeepaliveProcClass;

struct _CcnetKeepaliveProc {
    CcnetProcessor parent_instance;
};

struct _CcnetKeepaliveProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_keepalive_proc_get_type ();

#endif
