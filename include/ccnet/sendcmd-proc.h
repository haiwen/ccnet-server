/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_CMD_PROC_H
#define CCNET_CMD_PROC_H

#include <glib-object.h>

#include "processor.h"

#define CCNET_TYPE_SENDCMD_PROC                  (ccnet_sendcmd_proc_get_type ())
#define CCNET_SENDCMD_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SENDCMD_PROC, CcnetSendcmdProc))
#define CCNET_IS_SENDCMD_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SENDCMD_PROC))
#define CCNET_SENDCMD_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SENDCMD_PROC, CcnetSendcmdProcClass))
#define CCNET_IS_SENDCMD_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SENDCMD_PROC))
#define CCNET_SENDCMD_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SENDCMD_PROC, CcnetSendcmdProcClass))

typedef struct _CcnetSendcmdProc CcnetSendcmdProc;
typedef struct _CcnetSendcmdProcClass CcnetSendcmdProcClass;

typedef int (*SendcmdProcRcvrspCallback) (const char *code, char *content,
                                          int clen, void *data);

struct _CcnetSendcmdProc {
    CcnetProcessor parent_instance;

    SendcmdProcRcvrspCallback rcvrsp_cb;
    void      *cb_data;
};

struct _CcnetSendcmdProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_sendcmd_proc_get_type ();

int ccnet_sendcmd_proc_send_command (CcnetSendcmdProc *proc, const char *cmd);
void ccnet_sendcmd_proc_set_rcvrsp_cb (CcnetSendcmdProc *proc,
                                       SendcmdProcRcvrspCallback rcvrsp_cb,
                                       void *data);

#endif
