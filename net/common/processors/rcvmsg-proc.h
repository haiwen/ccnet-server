/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_RCVMSG_PROC_H
#define CCNET_RCVMSG_PROC_H

#include <glib-object.h>
#include "processor.h"

#define CCNET_TYPE_RCVMSG_PROC                  (ccnet_rcvmsg_proc_get_type ())
#define CCNET_RCVMSG_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_RCVMSG_PROC, CcnetRcvmsgProc))
#define CCNET_IS_RCVMSG_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_RCVMSG_PROC))
#define CCNET_RCVMSG_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_RCVMSG_PROC, CcnetRcvmsgProcClass))
#define CCNET_IS_RCVMSG_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_RCVMSG_PROC))
#define CCNET_RCVMSG_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_RCVMSG_PROC, CcnetRcvmsgProcClass))

typedef struct _CcnetRcvmsgProc CcnetRcvmsgProc;
typedef struct _CcnetRcvmsgProcClass CcnetRcvmsgProcClass;

struct _CcnetRcvmsgProc {
    CcnetProcessor parent_instance;
};

struct _CcnetRcvmsgProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_rcvmsg_proc_get_type ();

#endif
