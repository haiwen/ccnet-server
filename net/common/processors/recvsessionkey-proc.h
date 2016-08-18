/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_RECVSESSIONKEY_PROC_H
#define CCNET_RECVSESSIONKEY_PROC_H

#include <glib-object.h>


#define CCNET_TYPE_RECVSESSIONKEY_PROC                  (ccnet_recvsessionkey_proc_get_type ())
#define CCNET_RECVSESSIONKEY_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_RECVSESSIONKEY_PROC, CcnetRecvsessionkeyProc))
#define CCNET_IS_RECVSESSIONKEY_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_RECVSESSIONKEY_PROC))
#define CCNET_RECVSESSIONKEY_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_RECVSESSIONKEY_PROC, CcnetRecvsessionkeyProcClass))
#define IS_CCNET_RECVSESSIONKEY_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_RECVSESSIONKEY_PROC))
#define CCNET_RECVSESSIONKEY_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_RECVSESSIONKEY_PROC, CcnetRecvsessionkeyProcClass))

typedef struct _CcnetRecvsessionkeyProc CcnetRecvsessionkeyProc;
typedef struct _CcnetRecvsessionkeyProcClass CcnetRecvsessionkeyProcClass;

struct _CcnetRecvsessionkeyProc {
    CcnetProcessor parent_instance;
};

struct _CcnetRecvsessionkeyProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_recvsessionkey_proc_get_type ();

#endif

