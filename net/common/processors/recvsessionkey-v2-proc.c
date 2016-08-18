/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "session.h"
#include "common.h"
#include "processor.h"
#include "peer.h"
#include  "peer-mgr.h"
#include "log.h"
#include "rsa.h"

#include "recvsessionkey-v2-proc.h"

extern CcnetSession *session;

#define SC_SESSION_KEY "300"
#define SS_SESSION_KEY "session key"
#define SC_ALREADY_HAS_KEY "301"
#define SS_ALREADY_HAS_KEY "already has your session key"
#define SC_NO_ENCRYPT "303"
#define SS_NO_ENCRYPT "Donot encrypt channel"
#define SC_BAD_KEY "400"
#define SS_BAD_KEY "bad session key"


typedef struct  {
    int encrypt_channel;
} CcnetRecvskey2ProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_RECVSKEY2_PROC, CcnetRecvskey2ProcPriv))

#define USE_PRIV \
    CcnetRecvskey2ProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (CcnetRecvskey2Proc, ccnet_recvskey2_proc, CCNET_TYPE_PROCESSOR)



static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (ccnet_recvskey2_proc_parent_class)->release_resource (processor);
}


static void
ccnet_recvskey2_proc_class_init (CcnetRecvskey2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "receive-skey2";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (CcnetRecvskey2ProcPriv));
}

static void
ccnet_recvskey2_proc_init (CcnetRecvskey2Proc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;

    if (processor->peer->session_key) {
        ccnet_processor_send_response (processor,
                                       SC_ALREADY_HAS_KEY,
                                       SS_ALREADY_HAS_KEY,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (argc == 1 && g_strcmp0(argv[0], "--enc-channel") == 0)
        priv->encrypt_channel = 1;
    else
        priv->encrypt_channel = 0;

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
    USE_PRIV;

    if (strcmp(code, SC_SESSION_KEY) == 0) {
        if (processor->peer->session_key) {
            ccnet_processor_send_response (processor,
                                           SC_ALREADY_HAS_KEY,
                                           SS_ALREADY_HAS_KEY,
                                           NULL, 0);
            ccnet_processor_done (processor, TRUE);
            return;
        }

        if (update_peer_session_key (processor->peer, content, clen) < 0) {
            ccnet_processor_send_response (processor,
                                           SC_BAD_KEY, SS_BAD_KEY,
                                           NULL, 0);
            ccnet_processor_done (processor, FALSE);
            return;
        }

        if (priv->encrypt_channel) {
            /* peer ask to encrypt channel, check whether we want it too */
            if (ccnet_session_should_encrypt_channel(processor->session)) {
                /* send the ok reply first */
                ccnet_processor_send_response (processor,
                                               SC_OK, SS_OK,
                                               NULL, 0);
                /* now setup encryption */
                if (ccnet_peer_prepare_channel_encryption (processor->peer) < 0)
                    /* this is very rare, we just print a warning */
                    ccnet_warning ("Error in prepare channel encryption\n");
            } else
                ccnet_processor_send_response (
                    processor, SC_NO_ENCRYPT, SS_NO_ENCRYPT, NULL, 0);
        } else
            ccnet_processor_send_response (
                processor, SC_OK, SS_OK, NULL, 0);

        ccnet_peer_manager_on_peer_session_key_received (processor->peer->manager,
                                                         processor->peer);
        ccnet_processor_done (processor, TRUE);
        return;
    }
     
    ccnet_warning ("[recv session key] bad update %s:%s\n",
                   code, code_msg);
    ccnet_processor_done (processor, FALSE);
}
