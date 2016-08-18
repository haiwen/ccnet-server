/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_MQSERVER_PROC_H
#define CCNET_MQSERVER_PROC_H

#include <glib-object.h>

#include "processor.h"
#include "message.h"

#define CCNET_TYPE_MQSERVER_PROC                  (ccnet_mqserver_proc_get_type ())
#define CCNET_MQSERVER_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_MQSERVER_PROC, CcnetMqserverProc))
#define CCNET_IS_MQSERVER_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_MQSERVER_PROC))
#define CCNET_MQSERVER_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_MQSERVER_PROC, CcnetMqserverProcClass))
#define CCNET_IS_MQSERVER_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_MQSERVER_PROC))
#define CCNET_MQSERVER_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_MQSERVER_PROC, CcnetMqserverProcClass))

typedef struct _CcnetMqserverProc CcnetMqserverProc;
typedef struct _CcnetMqserverProcClass CcnetMqserverProcClass;

struct _CcnetMqserverProc {
    CcnetProcessor parent_instance;
};

struct _CcnetMqserverProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_mqserver_proc_get_type ();

void ccnet_mqserver_proc_put_message (CcnetProcessor *processor,
                                      CcnetMessage *message);

#endif
