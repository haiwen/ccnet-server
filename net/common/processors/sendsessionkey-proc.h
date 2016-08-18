/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_SENDSESSIONKEY_PROC_H
#define CCNET_SENDSESSIONKEY_PROC_H

#include <glib-object.h>


#define CCNET_TYPE_SENDSESSIONKEY_PROC                  (ccnet_sendsessionkey_proc_get_type ())
#define CCNET_SENDSESSIONKEY_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SENDSESSIONKEY_PROC, CcnetSendsessionkeyProc))
#define CCNET_IS_SENDSESSIONKEY_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SENDSESSIONKEY_PROC))
#define CCNET_SENDSESSIONKEY_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SENDSESSIONKEY_PROC, CcnetSendsessionkeyProcClass))
#define IS_CCNET_SENDSESSIONKEY_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SENDSESSIONKEY_PROC))
#define CCNET_SENDSESSIONKEY_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SENDSESSIONKEY_PROC, CcnetSendsessionkeyProcClass))

typedef struct _CcnetSendsessionkeyProc CcnetSendsessionkeyProc;
typedef struct _CcnetSendsessionkeyProcClass CcnetSendsessionkeyProcClass;

struct _CcnetSendsessionkeyProc {
    CcnetProcessor parent_instance;
};

struct _CcnetSendsessionkeyProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_sendsessionkey_proc_get_type ();

#endif

