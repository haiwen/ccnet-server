/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "peer.h"
#include "message.h"
#include "session.h"
#include "message-manager.h"
#include "peer-mgr.h"
#include "rcvmsg-proc.h"
#include "algorithms.h"

#define DEBUG_FLAG CCNET_DEBUG_MESSAGE
#include "log.h"

static int rcv_msg_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor, 
                           char *code, char *code_msg,
                           char *content, int clen);


G_DEFINE_TYPE (CcnetRcvmsgProc, ccnet_rcvmsg_proc, CCNET_TYPE_PROCESSOR)

static void
ccnet_rcvmsg_proc_class_init (CcnetRcvmsgProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "rcvmsg-proc";
    proc_class->start = rcv_msg_start;
    proc_class->handle_update = handle_update;
}

static void
ccnet_rcvmsg_proc_init (CcnetRcvmsgProc *processor)
{
}

static int rcv_msg_start (CcnetProcessor *processor, int argc, char **argv)
{
    ccnet_processor_send_response (processor, "200", "OK", NULL, 0);
    return 0;
}

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    CcnetMessage *msg;

    if (processor->peer->is_local) {
        msg = ccnet_message_from_string_local (content, clen);
        ccnet_send_message (processor->session, msg);
        ccnet_message_unref (msg);
    } else {
        msg = ccnet_message_from_string (content, clen);
        if (!msg) {
            g_warning ("Wrong message format.\n");
            ccnet_processor_done (processor, FALSE);
            return;
        }

        msg->rtime = time(NULL);
        ccnet_debug ("[msg] Received a message : %s - %.10s\n", 
                     msg->app, msg->body);

        int ret = ccnet_recv_message (processor->session, msg);
        if (ret == -1) {
            ccnet_message ("[msg] Message from %.8s permission error\n", 
                           msg->from);
            ccnet_processor_send_response (processor, SC_PERM_ERR,
                                           SS_PERM_ERR, NULL, 0);
            ccnet_processor_done (processor, TRUE);
            ccnet_message_unref (msg);
            return;
        }

        ccnet_message_unref (msg);
    }

    ccnet_processor_send_response (processor, "200", "OK", NULL, 0);
    ccnet_processor_done (processor, TRUE);
}
