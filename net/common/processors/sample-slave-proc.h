/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_SAMPLESLAVE_PROC_H
#define CCNET_SAMPLESLAVE_PROC_H

#include <glib-object.h>
#include "processor.h"

#define CCNET_TYPE_SAMPLE_SLAVE_PROC                  (ccnet_sample_slave_proc_get_type ())
#define CCNET_SAMPLE_SLAVE_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SAMPLE_SLAVE_PROC, CcnetSampleSlaveProc))
#define CCNET_IS_SAMPLE_SLAVE_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SAMPLE_SLAVE_PROC))
#define CCNET_SAMPLE_SLAVE_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SAMPLE_SLAVE_PROC, CcnetSampleSlaveProcClass))
#define CCNET_IS_SAMPLE_SLAVE_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SAMPLE_SLAVE_PROC))
#define CCNET_SAMPLE_SLAVE_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SAMPLE_SLAVE_PROC, CcnetSampleSlaveProcClass))

typedef struct _CcnetSampleSlaveProc CcnetSampleSlaveProc;
typedef struct _CcnetSampleSlaveProcClass CcnetSampleSlaveProcClass;

struct _CcnetSampleSlaveProc {
    CcnetProcessor parent_instance;
};

struct _CcnetSampleSlaveProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_sample_slave_proc_get_type ();

#endif
