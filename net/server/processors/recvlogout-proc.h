/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_RECVLOGOUT_PROC_H
#define CCNET_RECVLOGOUT_PROC_H

#include <glib-object.h>
#include <processor.h>


#define CCNET_TYPE_RECVLOGOUT_PROC                  (ccnet_recvlogout_proc_get_type ())
#define CCNET_RECVLOGOUT_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_RECVLOGOUT_PROC, CcnetRecvlogoutProc))
#define CCNET_IS_RECVLOGOUT_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_RECVLOGOUT_PROC))
#define CCNET_RECVLOGOUT_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_RECVLOGOUT_PROC, CcnetRecvlogoutProcClass))
#define IS_CCNET_RECVLOGOUT_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_RECVLOGOUT_PROC))
#define CCNET_RECVLOGOUT_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_RECVLOGOUT_PROC, CcnetRecvlogoutProcClass))

typedef struct _CcnetRecvlogoutProc CcnetRecvlogoutProc;
typedef struct _CcnetRecvlogoutProcClass CcnetRecvlogoutProcClass;

struct _CcnetRecvlogoutProc {
    CcnetProcessor parent_instance;
};

struct _CcnetRecvlogoutProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_recvlogout_proc_get_type ();

#endif

