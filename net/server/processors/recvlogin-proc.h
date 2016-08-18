/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_RECVLOGIN_PROC_H
#define CCNET_RECVLOGIN_PROC_H

#include <glib-object.h>


#define CCNET_TYPE_RECVLOGIN_PROC                  (ccnet_recvlogin_proc_get_type ())
#define CCNET_RECVLOGIN_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_RECVLOGIN_PROC, CcnetRecvloginProc))
#define CCNET_IS_RECVLOGIN_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_RECVLOGIN_PROC))
#define CCNET_RECVLOGIN_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_RECVLOGIN_PROC, CcnetRecvloginProcClass))
#define IS_CCNET_RECVLOGIN_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_RECVLOGIN_PROC))
#define CCNET_RECVLOGIN_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_RECVLOGIN_PROC, CcnetRecvloginProcClass))

typedef struct _CcnetRecvloginProc CcnetRecvloginProc;
typedef struct _CcnetRecvloginProcClass CcnetRecvloginProcClass;

struct _CcnetRecvloginProc {
    CcnetProcessor parent_instance;
};

struct _CcnetRecvloginProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_recvlogin_proc_get_type ();

#endif

