/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_SAMPLE_PROC_H
#define CCNET_SAMPLE_PROC_H

#include <glib-object.h>

#include "processor.h"

#define CCNET_TYPE_SAMPLE_PROC                  (ccnet_sample_proc_get_type ())
#define CCNET_SAMPLE_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SAMPLE_PROC, CcnetSampleProc))
#define CCNET_IS_SAMPLE_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SAMPLE_PROC))
#define CCNET_SAMPLE_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SAMPLE_PROC, CcnetSampleProcClass))
#define CCNET_IS_SAMPLE_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SAMPLE_PROC))
#define CCNET_SAMPLE_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SAMPLE_PROC, CcnetSampleProcClass))

typedef struct _CcnetSampleProc CcnetSampleProc;
typedef struct _CcnetSampleProcClass CcnetSampleProcClass;

struct _CcnetSampleProc {
    CcnetProcessor parent_instance;
};

struct _CcnetSampleProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_sample_proc_get_type ();

#endif
