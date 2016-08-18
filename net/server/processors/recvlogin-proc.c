/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "session.h"
#include "processor.h"
#include "log.h"
#include "peer.h"
#include "peer-mgr.h" 
#include "user-mgr.h" 
#include "recvlogin-proc.h"
#include "server-session.h"

#define SC_ERR_WRONG_PASSWD "301"
#define SS_ERR_WRONG_PASSWD "wrong password"

#define SC_INTERNAL_ERROR "302"
#define SS_INTERNAL_ERROR "relay internal error"


G_DEFINE_TYPE (CcnetRecvloginProc, ccnet_recvlogin_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (ccnet_recvlogin_proc_parent_class)->release_resource (processor);
}


static void
ccnet_recvlogin_proc_class_init (CcnetRecvloginProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;
}

static void
ccnet_recvlogin_proc_init (CcnetRecvloginProc *processor)
{
}

static void
check_emailuser (CcnetProcessor *processor,
                 const char *email, const char *passwd)
{
    char *prev_email;
    CcnetUserManager *user_mgr = 
        ((CcnetServerSession *)processor->session)->user_mgr;

    prev_email = ccnet_user_manager_get_binding_email (user_mgr,
                                                       processor->peer->id);
    if (prev_email) {
        /* This peer id has already been binded to some email address. */
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        
    } else if (!ccnet_user_manager_validate_emailuser (user_mgr,
                                               email, passwd)) {
        
        ccnet_processor_send_response (processor, SC_ERR_WRONG_PASSWD,
                                       SS_ERR_WRONG_PASSWD, NULL, 0);

    } else {
        CcnetPeer *peer = processor->peer;
        /* ccnet_peer_manager_add_role (session->peer_mgr, peer, "MyClient"); */
        /* ccnet_debug ("add role 'MyClient' for peer %.10s\n", peer->id); */
        if (ccnet_user_manager_add_binding (user_mgr, email, 
                                            peer->id) < 0) {
            ccnet_warning ("Failed to add binding for email(%s), user(%.10s)\n",
                           email, peer->id);

            ccnet_processor_send_response (processor,
                                           SC_INTERNAL_ERROR,
                                           SS_INTERNAL_ERROR,
                                           NULL, 0);
        }
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
    }
    g_free (prev_email);
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    if (argc != 2 || !argv[0] || !argv[1]) {
        ccnet_processor_error (processor, SC_BAD_ARGS, SS_BAD_ARGS);
        return -1;
    }
    char *email = argv[0];
    char *passwd = argv[1];
    /* ccnet_message ("receive login info from %s : email(%s), passwd(%s)\n", */
    /*                processor->peer->id, email, passwd); */

    check_emailuser (processor, email, passwd);
    ccnet_processor_done(processor, TRUE);

    return 0;
}


static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
}
