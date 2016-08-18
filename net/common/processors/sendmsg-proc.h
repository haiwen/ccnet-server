/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_SENDMSG_PROC_H
#define CCNET_SENDMSG_PROC_H

#include <glib-object.h>

#include "processor.h"

#define CCNET_TYPE_SENDMSG_PROC                  (ccnet_sendmsg_proc_get_type ())
#define CCNET_SENDMSG_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SENDMSG_PROC, CcnetSendmsgProc))
#define CCNET_IS_SENDMSG_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SENDMSG_PROC))
#define CCNET_SENDMSG_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SENDMSG_PROC, CcnetSendmsgProcClass))
#define CCNET_IS_SENDMSG_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SENDMSG_PROC))
#define CCNET_SENDMSG_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SENDMSG_PROC, CcnetSendmsgProcClass))

typedef struct _CcnetSendmsgProc CcnetSendmsgProc;
typedef struct _CcnetSendmsgProcClass CcnetSendmsgProcClass;

struct _CcnetSendmsgProc {
    CcnetProcessor parent_instance;
};

struct _CcnetSendmsgProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_sendmsg_proc_get_type ();

int ccnet_sendmsg_proc_set_msg (CcnetSendmsgProc *sendmsg_proc, 
                                CcnetMessage *msg);

#endif
