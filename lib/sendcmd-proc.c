/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <config.h>

#include <stdio.h>
#include <string.h>

#include "ccnet-client.h"
#include "sendcmd-proc.h"

enum {
    INIT,
    REQUEST_SENT,
    CONNECTED
};

typedef struct  {
    int    persist : 1;
} CcnetSendcmdProcPriv;

#define GET_PRIV(o)                                                     \
    (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_SENDCMD_PROC, CcnetSendcmdProcPriv))

static int send_cmd_start (CcnetProcessor *processor, int argc, char **argv);

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);


G_DEFINE_TYPE (CcnetSendcmdProc, ccnet_sendcmd_proc, CCNET_TYPE_PROCESSOR);

static void
ccnet_sendcmd_proc_class_init (CcnetSendcmdProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = send_cmd_start;
    proc_class->name = "sendcmd-proc";
    proc_class->handle_response = handle_response;

    g_type_class_add_private (klass, sizeof (CcnetSendcmdProcPriv));
}

static void
ccnet_sendcmd_proc_init (CcnetSendcmdProc *processor)
{
    CCNET_PROCESSOR (processor)->state = INIT;
}


static int
send_cmd_start (CcnetProcessor *processor, int argc, char **argv)
{
    char buf[256];
    CcnetSendcmdProcPriv *priv = GET_PRIV (processor);

    priv->persist = 0;

    while (0 < argc && argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'p':
            priv->persist = 1;
            break;
        default:
            break;
        }
        argc--; argv++;
    }
    if (priv->persist) {
        snprintf (buf, 256, "receive-cmd -p");
    } else {
        snprintf (buf, 256, "receive-cmd");
    }
    ccnet_client_send_request (processor->session,
                               REQUEST_ID (processor->id), buf);
    processor->state = REQUEST_SENT;

    return 0;
}



static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    CcnetSendcmdProcPriv *priv = GET_PRIV (processor);
    CcnetSendcmdProc *proc = (CcnetSendcmdProc *) processor;

    if (code[0] != '2') {
        g_warning ("Receive bad response %s %s\n", code, code_msg);
    }

    switch (processor->state) {
    case REQUEST_SENT:
        processor->state = CONNECTED;
        return;

    case CONNECTED:
        if (proc->rcvrsp_cb) {
            proc->rcvrsp_cb (code, content, clen, proc->cb_data);
        }
        break;
    default:
        break;
    }

    if (!priv->persist)
        ccnet_processor_done (processor, TRUE);
}

int
ccnet_sendcmd_proc_send_command (CcnetSendcmdProc *proc, const char *cmd)
{
    CcnetProcessor *processor = CCNET_PROCESSOR (proc);

/*
    if (processor->state != CONNECTED)
        return -1;
*/
    ccnet_client_send_update (processor->session, UPDATE_ID(processor->id), 
                              "200", NULL, 
                              cmd, strlen(cmd)+1); /* including '\0' */
    
    return 0;
}

void
ccnet_sendcmd_proc_set_rcvrsp_cb (CcnetSendcmdProc *proc,
                                  SendcmdProcRcvrspCallback rcvrsp_cb,
                                  void *data)
{
    proc->rcvrsp_cb = rcvrsp_cb;
    proc->cb_data = data;
}
