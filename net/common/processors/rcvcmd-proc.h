/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_RCVCMD_PROC_H
#define CCNET_RCVCMD_PROC_H

#include <glib-object.h>
#include "processor.h"

#define CCNET_TYPE_RCVCMD_PROC                  (ccnet_rcvcmd_proc_get_type ())
#define CCNET_RCVCMD_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_RCVCMD_PROC, CcnetRcvcmdProc))
#define CCNET_IS_RCVCMD_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_RCVCMD_PROC))
#define CCNET_RCVCMD_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_RCVCMD_PROC, CcnetRcvcmdProcClass))
#define CCNET_IS_RCVCMD_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_RCVCMD_PROC))
#define CCNET_RCVCMD_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_RCVCMD_PROC, CcnetRcvcmdProcClass))

typedef struct _CcnetRcvcmdProc CcnetRcvcmdProc;
typedef struct _CcnetRcvcmdProcClass CcnetRcvcmdProcClass;

struct _CcnetRcvcmdProc {
    CcnetProcessor parent_instance;
};

struct _CcnetRcvcmdProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_rcvcmd_proc_get_type ();

#endif
