/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*

  After we get a peer's pubkey, we generate a session key (symmetric) to
  encrypt important data.

            receive-session-key
  A     --------------------------->    B

             SC_SESSION_KEY (ask for session key)
        <---------------------------  


             SC_SESSION_KEY <key> (encrypted with B's pubkey)
        ---------------------------->

             SC_OK
        <-------------------------------
*/

#include <openssl/sha.h>
#include <openssl/rand.h>

#include "session.h"
#include "common.h"
#include "processor.h"
#include "peer-mgr.h"
#include "peer.h"
#include "log.h"
#include "rsa.h"

#include "sendsessionkey-proc.h"

#define SC_SESSION_KEY "300"
#define SS_SESSION_KEY "session key"
#define SC_ALREADY_HAS_KEY "301"
#define SS_ALREADY_HAS_KEY "already has your session key"
#define SC_BAD_KEY "302"
#define SS_BAD_KEY "bad session key"

enum {
    INIT = 0,
    REQUEST_SENT,
    SESSION_KEY_SENT,
};

typedef struct  {
    char key[40];
    int state;
} CcnetSendsessionkeyProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_SENDSESSIONKEY_PROC, CcnetSendsessionkeyProcPriv))

#define USE_PRIV \
    CcnetSendsessionkeyProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (CcnetSendsessionkeyProc, ccnet_sendsessionkey_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (ccnet_sendsessionkey_proc_parent_class)->release_resource (processor);
}


static void
ccnet_sendsessionkey_proc_class_init (CcnetSendsessionkeyProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "send-session-key";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (CcnetSendsessionkeyProcPriv));
}

static void
ccnet_sendsessionkey_proc_init (CcnetSendsessionkeyProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    if (argc != 0) {
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (processor->peer->session_key) {
        ccnet_warning ("peer %.10s already has session key\n",
                       processor->peer->id);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    ccnet_processor_send_request (processor, "receive-session-key");

    priv->state = REQUEST_SENT;

    return 0;
}

/* random bytes -> sha1 -> pubkey_encrypt -> transmit to peer */
static unsigned char *
generate_session_key (CcnetProcessor *processor, int *len_p)
{
    USE_PRIV;
    CcnetPeer *peer = processor->peer;
    unsigned char sha1[20];
    unsigned char *enc_out = NULL; 
    unsigned char random_buf[40];
    SHA_CTX s;

    RAND_bytes (random_buf, sizeof(random_buf));
    
    SHA1_Init (&s);
    SHA1_Update (&s, random_buf, sizeof(random_buf));
    SHA1_Final (sha1, &s);

    rawdata_to_hex (sha1, priv->key, 20);

    enc_out = public_key_encrypt (peer->pubkey, (unsigned char *)priv->key,
                                  40, len_p);

    if (*len_p <= 0) {
        g_free (enc_out);
        return NULL;
    }

    return enc_out;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    USE_PRIV;
    if (strcmp(code, SC_SESSION_KEY) == 0 && priv->state == REQUEST_SENT) {
        unsigned char *enc_out = NULL;
        int len = 0;

        enc_out = generate_session_key(processor, &len);
        if (enc_out) {
            ccnet_processor_send_update (processor,
                                         SC_SESSION_KEY,
                                         SS_SESSION_KEY,
                                         (char *)enc_out, len);
            g_free (enc_out);
            priv->state = SESSION_KEY_SENT;
            
        } else {
            ccnet_warning ("failed to generate session key for peer %.10s\n",
                           processor->peer->id);
            ccnet_processor_done (processor, FALSE);
        }

    } else if (strcmp(code, SC_OK) == 0 && priv->state == SESSION_KEY_SENT) {
        processor->peer->session_key = g_strndup(priv->key, 40);

        ccnet_peer_manager_on_peer_session_key_sent (processor->peer->manager,
                                                     processor->peer);

        ccnet_processor_done (processor, TRUE);
        
    } else if (strcmp(code, SC_ALREADY_HAS_KEY) == 0) {
        /* already has session key, skip */
        ccnet_processor_done (processor, TRUE);
        
    } else {
        ccnet_warning ("[send session key] bad response %s:%s\n",
                       code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}
