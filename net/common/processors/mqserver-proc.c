/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "peer.h"
#include "message.h"
#include "session.h"
#include "message-manager.h"
#include "mqserver-proc.h"
#include "algorithms.h"

#define DEBUG_FLAG CCNET_DEBUG_MESSAGE
#include "log.h"

#define SC_MSG "300"

enum {
    INIT,
    READY
};

typedef struct {
    int n_app;
    char **apps;
    int subscribed : 1;
} MqserverProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_MQSERVER_PROC, MqserverProcPriv))

static int mq_server_start (CcnetProcessor *processor, int argc, char **argv);

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

G_DEFINE_TYPE (CcnetMqserverProc, ccnet_mqserver_proc, CCNET_TYPE_PROCESSOR)


static void subscribe_message (CcnetProcessor *processor)
{
    MqserverProcPriv *priv = GET_PRIV (processor);
    CcnetMessageManager *msg_mgr = processor->session->msg_mgr;

    priv->subscribed = 1;
    ccnet_message_manager_subscribe_app (msg_mgr, processor,
                                         priv->n_app, priv->apps);    
}

static void unsubscribe_message (CcnetProcessor *processor)
{
    MqserverProcPriv *priv = GET_PRIV (processor);
    CcnetMessageManager *msg_mgr = processor->session->msg_mgr;

    if (priv->subscribed)
        ccnet_message_manager_unsubscribe_app (msg_mgr, processor,
                                               priv->n_app, priv->apps);    
}

static void release_resource (CcnetProcessor *processor)
{
    int i;
    MqserverProcPriv *priv = GET_PRIV (processor);

    unsubscribe_message(processor);

    for (i = 0; i < priv->n_app; ++i)
        g_free (priv->apps[i]);
    g_free (priv->apps);

    memset (priv, 0, sizeof(MqserverProcPriv));

    CCNET_PROCESSOR_CLASS(ccnet_mqserver_proc_parent_class)->release_resource(processor);
}



static void
ccnet_mqserver_proc_class_init (CcnetMqserverProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);
    /* GObjectClass *object_class = G_OBJECT_CLASS (klass); */

    proc_class->name = "mqserver-proc";
    proc_class->start = mq_server_start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (MqserverProcPriv));
}

static void
ccnet_mqserver_proc_init (CcnetMqserverProc *processor)
{
}


static int
mq_server_start (CcnetProcessor *processor, int argc, char **argv)
{
    MqserverProcPriv *priv = GET_PRIV (processor);
    int i;

    priv->n_app = argc;
    priv->apps = g_new (char*, argc);
    for (i = 0; i < argc; ++i)
        priv->apps[i] = g_strdup (argv[i]);

    subscribe_message (processor);

    ccnet_processor_send_response (processor, "200", "OK", NULL, 0);
    return 0;
}

static void send_message (CcnetProcessor *processor, CcnetMessage *message)
{
    GString *buf = g_string_new (NULL);

    ccnet_message_to_string_buf_local (message, buf);
    ccnet_processor_send_response (processor, SC_MSG, NULL,
                                   buf->str, buf->len+1);
    g_string_free (buf, TRUE);
}

void
ccnet_mqserver_proc_put_message (CcnetProcessor *processor,
                                 CcnetMessage *message)
{
    send_message (processor, message);
}


static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    /* MqserverProcPriv *priv = GET_PRIV (processor); */
    /* CcnetMessageManager *msg_mgr = processor->session->messageMgr; */

    if (code[0] != '3') {
        ccnet_warning ("received bad update: %s %s", code, code_msg);
        return;
    }

    if (code[2] == '0') {
        /* SC_MSG */
        CcnetMessage *msg;
        msg = ccnet_message_from_string_local (content, clen);

        /* ccnet_debug ("[msg] send msg: %.10s\n", msg->body); */

        ccnet_send_message (processor->session, msg);
        ccnet_message_unref (msg);
    } else if (code[2] == '1') {
        /* SC_UNSUBSCRIBE */
        ccnet_processor_done (processor, TRUE);
        return;
    }

    ccnet_processor_send_response (processor, "200", "OK", NULL, 0);
}
