/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "recvlogout-proc.h"

#include "session.h"
#include "processor.h"
#include "log.h"
#include "peer.h"
#include "peer-mgr.h" 
#include "user-mgr.h" 
#include "server-session.h"

G_DEFINE_TYPE (CcnetRecvlogoutProc, ccnet_recvlogout_proc, CCNET_TYPE_PROCESSOR)

#define SC_NO_BINDING "301"
#define SS_NO_BINDING "Not binded yet"

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (ccnet_recvlogout_proc_parent_class)->release_resource (processor);
}


static void
ccnet_recvlogout_proc_class_init (CcnetRecvlogoutProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;
}

static void
ccnet_recvlogout_proc_init (CcnetRecvlogoutProc *processor)
{
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    CcnetUserManager *user_mgr = 
        ((CcnetServerSession *)processor->session)->user_mgr;
    
    if (argc != 0) {
        ccnet_processor_error (processor, SC_BAD_ARGS, SS_BAD_ARGS);
        return -1;
    }

    CcnetPeer *peer = processor->peer;
    char *email;

    /* ccnet_peer_manager_remove_role (session->peer_mgr, peer, "MyClient"); */

    email = ccnet_user_manager_get_binding_email (user_mgr, peer->id);
    if (!email) {
        ccnet_processor_send_response (processor, SC_NO_BINDING,
                                       SS_NO_BINDING, NULL, 0);
    } else {
        ccnet_user_manager_remove_one_binding (user_mgr,
                                               email, peer->id);
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
    }

    g_free (email);
    ccnet_processor_done (processor, TRUE);
    return 0;
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
}
