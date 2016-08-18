/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_ECHO_PROC_H
#define CCNET_ECHO_PROC_H

#include <glib-object.h>

#include "processor.h"

#define CCNET_TYPE_ECHO_PROC                  (ccnet_echo_proc_get_type ())
#define CCNET_ECHO_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_ECHO_PROC, CcnetEchoProc))
#define CCNET_IS_ECHO_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_ECHO_PROC))
#define CCNET_ECHO_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_ECHO_PROC, CcnetEchoProcClass))
#define CCNET_IS_ECHO_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_ECHO_PROC))
#define CCNET_ECHO_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_ECHO_PROC, CcnetEchoProcClass))

typedef struct _CcnetEchoProc CcnetEchoProc;
typedef struct _CcnetEchoProcClass CcnetEchoProcClass;

struct _CcnetEchoProc {
    CcnetProcessor parent_instance;
};

struct _CcnetEchoProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_echo_proc_get_type ();

#endif
