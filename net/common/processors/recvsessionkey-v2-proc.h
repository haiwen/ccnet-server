/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_RECVSKEY2_PROC_H
#define CCNET_RECVSKEY2_PROC_H

#include <glib-object.h>


#define CCNET_TYPE_RECVSKEY2_PROC                  (ccnet_recvskey2_proc_get_type ())
#define CCNET_RECVSKEY2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_RECVSKEY2_PROC, CcnetRecvskey2Proc))
#define CCNET_IS_RECVSKEY2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_RECVSKEY2_PROC))
#define CCNET_RECVSKEY2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_RECVSKEY2_PROC, CcnetRecvskey2ProcClass))
#define IS_CCNET_RECVSKEY2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_RECVSKEY2_PROC))
#define CCNET_RECVSKEY2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_RECVSKEY2_PROC, CcnetRecvskey2ProcClass))

typedef struct _CcnetRecvskey2Proc CcnetRecvskey2Proc;
typedef struct _CcnetRecvskey2ProcClass CcnetRecvskey2ProcClass;

struct _CcnetRecvskey2Proc {
    CcnetProcessor parent_instance;
};

struct _CcnetRecvskey2ProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_recvskey2_proc_get_type ();

#endif

