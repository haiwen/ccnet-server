/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <config.h>

#include <stdio.h>

#include "ccnet-client.h"
#include "mqclient-proc.h"

#define SC_MSG "300"
#define SC_UNSUBSCRIBE "301"

enum {
    INIT,
    REQUEST_SENT,
    READY
};

enum {
    RECV_MSG_SIG,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static int mq_client_start (CcnetProcessor *processor, int argc, char **argv);

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);


G_DEFINE_TYPE (CcnetMqclientProc, ccnet_mqclient_proc, CCNET_TYPE_PROCESSOR)

static void
ccnet_mqclient_proc_class_init (CcnetMqclientProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = mq_client_start;
    proc_class->handle_response = handle_response;
    proc_class->name = "mqclient-proc";

    signals[RECV_MSG_SIG] = 
        g_signal_new ("recv-msg", CCNET_TYPE_MQCLIENT_PROC ,
                      G_SIGNAL_RUN_LAST,
                      0,
                      NULL, NULL, /* no accumulator */
                      g_cclosure_marshal_VOID__OBJECT,
                      G_TYPE_NONE, 1, CCNET_TYPE_MESSAGE);
}

static void
ccnet_mqclient_proc_init (CcnetMqclientProc *processor)
{
    CCNET_PROCESSOR (processor)->state = INIT;
}

static int
mq_client_start (CcnetProcessor *processor, int argc, char **argv)
{
    GString *buf;
    int i;

    buf = g_string_new ("mq-server");
    for (i = 0; i < argc; ++i) {
        g_string_append (buf, " ");
        g_string_append (buf, argv[i]);
    }

    ccnet_client_send_request (processor->session, REQUEST_ID (processor->id),
                               buf->str);
    processor->state = REQUEST_SENT;

    g_string_free (buf, TRUE);
    return 0;
}

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    CcnetMqclientProc *proc = (CcnetMqclientProc *) processor;
    CcnetMessage *msg;

    switch (processor->state) {
    case REQUEST_SENT:
        if (code[0] != '2') {
            g_warning ("receive bad response: %s %s\n", code, code_msg);
            ccnet_processor_done (processor, FALSE);
            return;
        }

        processor->state = READY;
        break;
    case READY:
        if (code[0] != '2' && code[0] != '3') {
            g_warning ("receive bad response: %s %s\n", code, code_msg);
            return;
        }

        /* message notification. */
        if (code[0] == '3' && code[2] == '0') {
            msg = ccnet_message_from_string (content, clen);
            if (!msg) {
                g_warning ("Wrong message format.\n");
                ccnet_processor_done (processor, FALSE);
                break;
            }
            if (proc->message_got_cb)
                proc->message_got_cb (msg, proc->cb_data);
            g_signal_emit (proc, signals[RECV_MSG_SIG], 0, msg);
            ccnet_message_free (msg);
        }

        break;
    default:
        break;
    }
}

void ccnet_mqclient_proc_set_message_got_cb (CcnetMqclientProc *processor,
                                             MessageGotCB callback,
                                             void *cb_data)
{
    processor->message_got_cb = callback;
    processor->cb_data = cb_data;
}

void ccnet_mqclient_proc_put_message (CcnetMqclientProc *proc,
                                      CcnetMessage *message)
{
    CcnetProcessor *processor = (CcnetProcessor *) proc;
    GString *msg_buf;

    msg_buf = g_string_new (NULL);

    ccnet_message_to_string_buf (message, msg_buf);
    ccnet_client_send_update (processor->session, UPDATE_ID(processor->id),
                              SC_MSG, NULL, msg_buf->str, msg_buf->len+1);
    g_string_free (msg_buf, TRUE);
}

void ccnet_mqclient_proc_unsubscribe_apps (CcnetMqclientProc *proc)
{
    CcnetProcessor *processor = (CcnetProcessor *) proc;

    ccnet_client_send_update (processor->session, UPDATE_ID(processor->id),
                              SC_UNSUBSCRIBE, NULL, NULL, 0);
    ccnet_processor_done (processor, TRUE);
}
