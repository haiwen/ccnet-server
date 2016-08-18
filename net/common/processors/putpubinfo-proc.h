/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_PUTPUBINFO_PROC_H
#define CCNET_PUTPUBINFO_PROC_H

#include <glib-object.h>
#include "processor.h"

#define CCNET_TYPE_PUTPUBINFO_PROC                  (ccnet_putpubinfo_proc_get_type ())
#define CCNET_PUTPUBINFO_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_PUTPUBINFO_PROC, CcnetPutpubinfoProc))
#define CCNET_IS_PUTPUBINFO_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_PUTPUBINFO_PROC))
#define CCNET_PUTPUBINFO_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_PUTPUBINFO_PROC, CcnetPutpubinfoProcClass))
#define CCNET_IS_PUTPUBINFO_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_PUTPUBINFO_PROC))
#define CCNET_PUTPUBINFO_PROC_PUT_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_PUTPUBINFO_PROC, CcnetPutpubinfoProcClass))

typedef struct _CcnetPutpubinfoProc CcnetPutpubinfoProc;
typedef struct _CcnetPutpubinfoProcClass CcnetPutpubinfoProcClass;

struct _CcnetPutpubinfoProc {
    CcnetProcessor parent_instance;
};

struct _CcnetPutpubinfoProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_putpubinfo_proc_get_type ();

#endif
