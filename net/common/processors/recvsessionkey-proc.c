/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "session.h"
#include "common.h"
#include "processor.h"
#include "peer.h"
#include  "peer-mgr.h"
#include "log.h"
#include "rsa.h"

#include "recvsessionkey-proc.h"

extern CcnetSession *session;

#define SC_SESSION_KEY "300"
#define SS_SESSION_KEY "session key"
#define SC_ALREADY_HAS_KEY "301"
#define SS_ALREADY_HAS_KEY "already has your session key"
#define SC_BAD_KEY "302"
#define SS_BAD_KEY "bad session key"

G_DEFINE_TYPE (CcnetRecvsessionkeyProc, ccnet_recvsessionkey_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (ccnet_recvsessionkey_proc_parent_class)->release_resource (processor);
}


static void
ccnet_recvsessionkey_proc_class_init (CcnetRecvsessionkeyProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "receive-session-key";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;
}

static void
ccnet_recvsessionkey_proc_init (CcnetRecvsessionkeyProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    if (argc != 0) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (processor->peer->session_key) {
        ccnet_processor_send_response (processor,
                                       SC_ALREADY_HAS_KEY,
                                       SS_ALREADY_HAS_KEY,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    ccnet_processor_send_response (processor,
                                   SC_SESSION_KEY, SS_SESSION_KEY,
                                   NULL, 0);

    return 0;
}

static unsigned char *
decrypt_data (CcnetPeer *peer, const char *content, int clen, int *len_p)
{
    RSA *privkey = session->privkey;
    unsigned char *buf;

    buf = private_key_decrypt(privkey, (unsigned char *)content,
                              clen, len_p);
    if (*len_p <= 0) {
        ccnet_warning ("failed to decrypt session key from peer %.10s",
                       peer->id);
        g_free (buf);
        buf = NULL;
    }

    return buf;
}

static gboolean
update_peer_session_key (CcnetPeer *peer,
                         const char *content,
                         int clen)
{
    char *buf;
    int key_len = 0;

    if (peer->session_key) {
        ccnet_warning ("[recv session key] peer %.10s already has a session key",
                       peer->id);
        return FALSE;
    }

    buf = (char *)decrypt_data (peer, content, clen, &key_len);
    if (buf) {
        peer->session_key = g_strndup(buf, key_len);
        g_free (buf);
        return TRUE;
    } else {
        ccnet_warning ("faied to decrypt session key"); 
        return FALSE;
    }
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    if (strcmp(code, SC_SESSION_KEY) == 0) {
        if (processor->peer->session_key) {
            ccnet_processor_send_response (processor,
                                           SC_ALREADY_HAS_KEY,
                                           SS_ALREADY_HAS_KEY,
                                           NULL, 0);
            ccnet_processor_done (processor, TRUE);
            
        } else if (update_peer_session_key (processor->peer, content, clen)) {
            ccnet_processor_send_response (processor,
                                           SC_OK, SS_OK,
                                           NULL, 0);

            ccnet_peer_manager_on_peer_session_key_received (processor->peer->manager,
                                                             processor->peer);

            ccnet_processor_done (processor, TRUE);
        } else {
            ccnet_processor_send_response (processor,
                                           SC_BAD_KEY, SS_BAD_KEY,
                                           NULL, 0);
            ccnet_processor_done (processor, FALSE);
        }
        
    } else {
        ccnet_warning ("[recv session key] bad update %s:%s\n",
                       code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}
