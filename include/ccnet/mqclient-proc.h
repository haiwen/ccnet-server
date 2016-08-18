/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_MQCLIENT_PROC_H
#define CCNET_MQCLIENT_PROC_H

#include <glib-object.h>

#include "processor.h"
#include "message.h"

#define CCNET_TYPE_MQCLIENT_PROC                  (ccnet_mqclient_proc_get_type ())
#define CCNET_MQCLIENT_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_MQCLIENT_PROC, CcnetMqclientProc))
#define CCNET_IS_MQCLIENT_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_MQCLIENT_PROC))
#define CCNET_MQCLIENT_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_MQCLIENT_PROC, CcnetMqclientProcClass))
#define CCNET_IS_MQCLIENT_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_MQCLIENT_PROC))
#define CCNET_MQCLIENT_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_MQCLIENT_PROC, CcnetMqclientProcClass))

typedef struct _CcnetMqclientProc CcnetMqclientProc;
typedef struct _CcnetMqclientProcClass CcnetMqclientProcClass;

typedef void (*MessageGotCB) (CcnetMessage *message, void *data);

struct _CcnetMqclientProc {
    CcnetProcessor parent_instance;
    
    MessageGotCB  message_got_cb;
    void         *cb_data;
};

struct _CcnetMqclientProcClass {
    CcnetProcessorClass parent_class;
};

void ccnet_mqclient_proc_set_message_got_cb (CcnetMqclientProc *,
                                             MessageGotCB, void *);

GType ccnet_mqclient_proc_get_type ();

void ccnet_mqclient_proc_put_message (CcnetMqclientProc *proc,
                                      CcnetMessage *message);

void ccnet_mqclient_proc_unsubscribe_apps (CcnetMqclientProc *proc);

#endif
