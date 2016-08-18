/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_SENDSKEY2_PROC_H
#define CCNET_SENDSKEY2_PROC_H

#include <glib-object.h>


#define CCNET_TYPE_SENDSKEY2_PROC                  (ccnet_sendskey2_proc_get_type ())
#define CCNET_SENDSKEY2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SENDSKEY2_PROC, CcnetSendskey2Proc))
#define CCNET_IS_SENDSKEY2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SENDSKEY2_PROC))
#define CCNET_SENDSKEY2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SENDSKEY2_PROC, CcnetSendskey2ProcClass))
#define IS_CCNET_SENDSKEY2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SENDSKEY2_PROC))
#define CCNET_SENDSKEY2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SENDSKEY2_PROC, CcnetSendskey2ProcClass))

typedef struct _CcnetSendskey2Proc CcnetSendskey2Proc;
typedef struct _CcnetSendskey2ProcClass CcnetSendskey2ProcClass;

struct _CcnetSendskey2Proc {
    CcnetProcessor parent_instance;
};

struct _CcnetSendskey2ProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_sendskey2_proc_get_type ();

#endif

