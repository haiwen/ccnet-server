/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_GETPUBINFO_PROC_H
#define CCNET_GETPUBINFO_PROC_H

#include <glib-object.h>
#include "processor.h"

#define CCNET_TYPE_GETPUBINFO_PROC                  (ccnet_getpubinfo_proc_get_type ())
#define CCNET_GETPUBINFO_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_GETPUBINFO_PROC, CcnetGetpubinfoProc))
#define CCNET_IS_GETPUBINFO_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_GETPUBINFO_PROC))
#define CCNET_GETPUBINFO_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_GETPUBINFO_PROC, CcnetGetpubinfoProcClass))
#define CCNET_IS_GETPUBINFO_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_GETPUBINFO_PROC))
#define CCNET_GETPUBINFO_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_GETPUBINFO_PROC, CcnetGetpubinfoProcClass))

typedef struct _CcnetGetpubinfoProc CcnetGetpubinfoProc;
typedef struct _CcnetGetpubinfoProcClass CcnetGetpubinfoProcClass;

struct _CcnetGetpubinfoProc {
    CcnetProcessor parent_instance;
};

struct _CcnetGetpubinfoProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_getpubinfo_proc_get_type ();

#endif
