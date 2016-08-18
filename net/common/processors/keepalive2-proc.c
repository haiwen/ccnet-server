/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>


#include "keepalive2-proc.h"

#include "peer.h"
#include "session.h"
#include "peer-mgr.h"

#include "processor.h"
#include "proc-factory.h"

#include "timer.h"

#include "rsa.h"
#include "string-util.h"
#include "utils.h"

#define DEBUG_FLAG CCNET_DEBUG_CONNECTION
#include "log.h"

/* Since we use only tcp, packet should not be lost,
   set a large time (3min). */
#define KEEPALIVE_INTERVAL                180000 /* 3min */

enum {
    INIT,
    WAIT_PUBKEY,
    WAIT_CHALLENGE,
    WAIT_KEEPALIVE,
    FULL
};


/*
  protocol:
       state
                   keepalive2
       INIT     ----------------->

               <-----------------  start keepalive
                      OK

                     310
   WAIT_PUBKEY  ----------------->
   (optional)  <-----------------

                  311 random_buf
 WAIT_CHALLENGE ----------------->
               <-----------------

  
                  300  <msg>
 WAIT_KEEPALIVE -----------------> 
               <-----------------
                      OK

     FULL (keepalive interval)

                  300  <msg>
 WAIT_KEEPALIVE -----------------> 
               <-----------------
                      OK

     FULL (keepalive interval)

     ....
 */


#define SC_BAD_KEEPALIVE "400"
#define SS_BAD_KEEPALIVE "Bad keepalive format"
#define SC_BAD_CHALLENGE "411"
#define SS_BAD_CHALLENGE "Bad challenge format"
#define SC_DECRYPT_ERROR "412"
#define SS_DECRYPT_ERROR "Decrypt error"


typedef struct  {
    unsigned char random_buf[40];
    int count;
} CcnetKeepalive2ProcPriv;

extern CcnetSession *session;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_KEEPALIVE2_PROC, CcnetKeepalive2ProcPriv))

#define USE_PRIV CcnetKeepalive2ProcPriv *priv = GET_PRIV (processor);


G_DEFINE_TYPE (CcnetKeepalive2Proc, ccnet_keepalive2_proc, CCNET_TYPE_PROCESSOR)


static int keepalive2_start (CcnetProcessor *processor, 
                                int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);
static void reset_timeout(CcnetProcessor *processor);
static void get_peer_pubinfo (CcnetPeer *peer);
 
static void proc_shutdown (CcnetProcessor *processor)
{
    CcnetPeer *peer = processor->peer;

    if (IS_SLAVE(processor))
        return;

    /* The shutdown of keepalive is only be called in
     * peer shutdown */
    /* g_assert (peer->in_shutdown); */
    if (!peer->in_shutdown)
        ccnet_warning ("Shutdown keepalive is not called from peer_shutdown\n");
}

static void
release_resource(CcnetProcessor *processor)
{
    processor->peer->keepalive_sending = 0;
    
    /* should always chain up */
    CCNET_PROCESSOR_CLASS(ccnet_keepalive2_proc_parent_class)->release_resource (processor);
}

static void
ccnet_keepalive2_proc_class_init (CcnetKeepalive2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "keepalive2-proc";
    proc_class->start = keepalive2_start;
    proc_class->handle_response = handle_response;
    proc_class->handle_update = handle_update;
    proc_class->shutdown = proc_shutdown;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof(CcnetKeepalive2ProcPriv));
}

static void
ccnet_keepalive2_proc_init (CcnetKeepalive2Proc *processor)
{
}

static void send_keepalive(CcnetProcessor *processor)
{
    USE_PRIV;

    char cntstr[64];

    sprintf(cntstr, "%d", priv->count++);
    ccnet_processor_send_update (processor, "300", cntstr,
                                 NULL, 0);
    /* ccnet_debug ("[Keepalive] Send keepavlie to peer %.8s #%s\n", */
    /*              processor->peer->id, cntstr->str); */

    processor->state = WAIT_KEEPALIVE;
}

static void send_request(CcnetProcessor *processor)
{
    char buf[64];
    snprintf (buf, 64, "keepalive2");
    ccnet_processor_send_request (processor, buf);
}

static void close_processor_in_timeout(CcnetProcessor *processor)
{
    CcnetPeer *peer = processor->peer;

    ccnet_debug ("[Conn] keepalive timeout current state is %d\n",
                 processor->state);

    ccnet_processor_done (processor, FALSE);
    ccnet_peer_shutdown (peer);
    peer->num_fails++;
}

static int timeout_cb(CcnetProcessor *processor)
{
    if (processor->state == FULL) {
        send_keepalive(processor);
        return TRUE;
    }

    close_processor_in_timeout(processor);
    return FALSE;
}

static void reset_timeout(CcnetProcessor *processor)
{
    if (processor->retry_timer)
        ccnet_timer_free(&processor->retry_timer);
    processor->retry_timer = ccnet_timer_new ((TimerCB)timeout_cb, processor,
                                             KEEPALIVE_INTERVAL);
}

static void close_processor(CcnetProcessor *processor)
{
    CcnetPeer *peer = processor->peer;

    ccnet_timer_free (&processor->retry_timer);
    ccnet_processor_done (processor, FALSE);
    ccnet_peer_shutdown (peer);
    peer->num_fails++;
}


static int keepalive2_start (CcnetProcessor *processor, 
                            int argc, char **argv)
{
    CcnetKeepalive2ProcPriv *priv = GET_PRIV (processor);

    if (IS_SLAVE(processor)) {
        ccnet_processor_send_response (processor, 
                                       SC_OK, SS_OK, NULL, 0);
        return 0;
    }

    /* master */
    priv->count = 0;
    processor->state = INIT;
    processor->peer->keepalive_sending = 1;
    send_request (processor);
    reset_timeout (processor);

    return 0;
}

struct Handler
{
    const char *code;
    void (*handler) (CcnetProcessor *processor, 
                     char *code, char *code_msg,
                     char *content, int clen);
};

struct Handler *
get_handler (char *code, struct Handler *tab)
{
    struct Handler *c;

    for (c = tab; c->code; c++) {
        if (c->code[0] == code[0] && c->code[1] == code[1]
            && c->code[2] == code[2])
            return c;
    }

    return NULL;
}


static void recv_keepalive_rsp(CcnetProcessor *processor, 
                              char *code, char *code_msg,
                              char *content, int clen);

static void recv_ok(CcnetProcessor *processor, 
                       char *code, char *code_msg,
                       char *content, int clen);

static void recv_pubkey(CcnetProcessor *processor, 
                        char *code, char *code_msg,
                        char *content, int clen);

static void verify_challenge(CcnetProcessor *processor, 
                             char *code, char *code_msg,
                             char *content, int clen);

static struct Handler rsp_handler_tab[] = {
    { "200", recv_ok }, 
    { "300", recv_keepalive_rsp },
    { "310", recv_pubkey },
    { "311", verify_challenge },
    { 0 },
};

static void send_challenge(CcnetProcessor *processor)
{
    CcnetKeepalive2ProcPriv *priv = GET_PRIV (processor);

    ccnet_debug ("[Keepalive] Before send challenge, check valid of id\n");
    char *id = id_from_pubkey(processor->peer->pubkey);
    if (g_strcmp0(id, processor->peer->id) != 0) {
        ccnet_debug ("[Keepalive] Peer id not conform to public key: %s %s\n",
                     id, processor->peer->id);
        close_processor (processor);
        g_free (id);
        return;
    }
    g_free (id);
    
    ccnet_debug ("[Keepalive] Send peer challenge to %s(%.8s)\n",
                 processor->peer->name, processor->peer->id);

    CcnetPeer *peer = processor->peer;
    unsigned char *buf;
    int len;

    RAND_pseudo_bytes (priv->random_buf, 40);
    buf = public_key_encrypt (peer->pubkey, priv->random_buf, 40, &len);
    if (len < 0) {
        ccnet_debug ("[Keepalive] Failed to encrypt challenge "
                     "with peer %s(%.8s)'s pubkey\n", peer->name, peer->id);
        close_processor (processor);
        g_free (buf);
        return;
    }
        
    ccnet_processor_send_update (processor, "311", NULL, (char *)buf, len);

    g_free(buf);
    processor->state = WAIT_CHALLENGE;
    reset_timeout (processor);
}

static void get_pubkey(CcnetProcessor *processor)
{
    ccnet_processor_send_update (processor,
                                 "310", NULL, NULL, 0);
    processor->state = WAIT_PUBKEY;
    reset_timeout(processor);
}

static void recv_ok(CcnetProcessor *processor, 
                    char *code, char *code_msg,
                    char *content, int clen)
{
    if (processor->state != INIT) {
        close_processor(processor);
        return;
    }
    
    if (processor->peer->pubkey) {
        ccnet_debug ("[Keepalive] Receive ok, send challenge\n");
        send_challenge(processor);
    } else {
        ccnet_debug ("[Keepalive] Receive ok, get pubkey\n");
        get_pubkey(processor);
    }
}

static void recv_pubkey(CcnetProcessor *processor, 
                        char *code, char *code_msg,
                        char *content, int clen)
{
    if (processor->state != WAIT_PUBKEY) {
        ccnet_debug ("[Keepalive] Receive public key not in WAIT_PUBKEY state\n");
        close_processor (processor);
        return;
    }

    if (clen == 0 || content[clen-1] != '\0') {
        ccnet_debug ("[Keepalive] Bad public key format\n");
        close_processor (processor);
        return;
    }

    ccnet_peer_set_pubkey (processor->peer, content);
    if (processor->peer->pubkey == NULL) {
        ccnet_debug ("[Keepalive] Bad public key format\n");
        close_processor (processor);
        return;
    }

    ccnet_debug ("[Keepalive] Receive pubkey, send challenge\n");
    send_challenge (processor);
}
    
static void recv_keepalive_rsp(CcnetProcessor *processor, 
                               char *code, char *code_msg,
                               char *content, int clen)
{
    /* ccnet_debug ("[Keepalive] Receive keepalive responese from peer %.8s #%s\n", */
    /*              processor->peer->id, code_msg); */
    processor->state = FULL;
}

static void on_send_skey_done (CcnetProcessor *processor,
                               gboolean success, void *data)
{
    if (!success && !processor->peer->in_shutdown) {
        /* try the old version */
        CcnetProcessor *p;
        CcnetProcFactory *factory = processor->session->proc_factory;
        CcnetPeer *peer = processor->peer;

        if (peer->session_key) {
            ccnet_warning ("peer %s already has session key\n", peer->id); 
            return;
        }

        p = ccnet_proc_factory_create_master_processor (
        factory, "send-session-key", peer);    
        if (!p) {
            ccnet_warning ("create send session key processor failed\n");
            return;
        }

        if (ccnet_processor_startl (p, NULL) < 0) {
            ccnet_warning ("start send session key processor failed\n");
            return;
        }
    }
}

static void
send_session_key (CcnetPeer *peer)
{
    CcnetProcessor *processor;
    CcnetProcFactory *factory = peer->manager->session->proc_factory;

    if (peer->session_key) {
        ccnet_warning ("peer %s already has session key\n", peer->id); 
        return;
    }

    processor = ccnet_proc_factory_create_master_processor (
        factory, "send-skey2", peer);    
    if (!processor) {
        ccnet_warning ("create send session key processor failed\n");
        return;
    }

    g_signal_connect (processor, "done",
                      G_CALLBACK(on_send_skey_done), NULL);

    if (ccnet_processor_startl (processor, NULL) < 0) {
        ccnet_warning ("start send session key processor failed\n");
        return;
    }
}

static void verify_challenge(CcnetProcessor *processor, 
                             char *code, char *code_msg,
                             char *content, int clen)
{
    CcnetKeepalive2ProcPriv *priv = GET_PRIV (processor);

    if (clen != 40 || memcmp(content, priv->random_buf, 40) != 0) {
        ccnet_debug ("[Conn] Peer Challenge failed\n");
        close_processor(processor);
        return;
    }

    ccnet_debug ("[Keepalive] Verify Peer Challenge\n");

    get_peer_pubinfo (processor->peer);
    /* ccnet_peer_manager_notify_peer_role (processor->peer->manager,  */
    /*                                      processor->peer); */

    if (strcmp(session->base.id, processor->peer->id) < 0)
        send_session_key (processor->peer);
        
    send_keepalive (processor);
    reset_timeout (processor);
    return;
}

static void handle_response (CcnetProcessor *processor, 
                             char *code, char *code_msg,
                             char *content, int clen)
{
    if (code[0] == '4' || code[0] == '5') {
        ccnet_warning ("[Keepalive] Error from peer %s %s\n",
                       code, code_msg);
        close_processor (processor);
        return;
    }

    struct Handler *handler = get_handler(code, rsp_handler_tab);
    if (!handler) {
        ccnet_processor_send_update (processor, SC_BAD_RESPONSE_CODE,
                                     SS_BAD_RESPONSE_CODE, NULL, 0);
        close_processor (processor);
        return;
    }

    handler->handler(processor, code, code_msg, content, clen);
}


/* update handle */

static void receive_keepalive(CcnetProcessor *processor, 
                              char *code, char *code_msg,
                              char *content, int clen);

static void send_pubkey(CcnetProcessor *processor, 
                        char *code, char *code_msg,
                        char *content, int clen);

static void response_challenge(CcnetProcessor *processor, 
                               char *code, char *code_msg,
                               char *content, int clen);


static struct Handler update_handler_tab[] = {
    { "300", receive_keepalive },
    { "310", send_pubkey },
    { "311", response_challenge },
    { 0 },
};



static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    if (code[0] == '4' || code[0] == '5') {
        ccnet_warning ("[Keepalive] Error from peer %s %s\n",
                       code, code_msg);
        ccnet_processor_done(processor, FALSE);
        return;
    }

    struct Handler *handler = get_handler(code, update_handler_tab);
    if (!handler) {
        ccnet_processor_send_response (processor,
                   SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE, NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return;
    }
    handler->handler(processor, code, code_msg, content, clen);
}

static void get_peer_pubinfo (CcnetPeer *peer)
{
    CcnetProcessor *newp;
    CcnetProcFactory *factory = peer->manager->session->proc_factory;
    
    newp = ccnet_proc_factory_create_master_processor (factory,
                                          "get-pubinfo", peer);
    if (newp == NULL) {
        ccnet_warning ("Create get pubinfo processor failed\n");
        return;
    }
    ccnet_processor_startl (newp, NULL);
}


static void receive_keepalive(CcnetProcessor *processor, 
                              char *code, char *code_msg,
                              char *content, int clen)
{
    /* ccnet_debug ("[Keepalive] Receive keepalive from %.8s #%s\n", */
    /*              processor->peer->id, code_msg); */
    ccnet_processor_send_response (
        processor, code, code_msg, NULL, 0);
}

static void send_pubkey(CcnetProcessor *processor, 
                        char *code, char *code_msg,
                        char *content, int clen)
{
    GString *str;
    
    str = public_key_to_gstring(processor->session->pubkey);
    ccnet_processor_send_response (processor, code, "", str->str, str->len+1);
}


static void response_challenge(CcnetProcessor *processor, 
                               char *code, char *code_msg,
                               char *content, int clen)
{
    unsigned char *buf;
    int decrypt_len;

    if (clen == 0) {
        ccnet_warning("Peer %s(%.8s) send bad format challenge\n",
                      processor->peer->name, processor->peer->id);
        ccnet_processor_send_response (
            processor, SC_BAD_CHALLENGE, SS_BAD_CHALLENGE, NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return;
    }
        
    buf = private_key_decrypt(processor->session->privkey,
                   (unsigned char *)content, clen, &decrypt_len);
    if (decrypt_len < 0) {
        ccnet_processor_send_response (
            processor, SC_DECRYPT_ERROR, SS_DECRYPT_ERROR, NULL, 0);
        ccnet_processor_done(processor, FALSE);
    } else
        ccnet_processor_send_response (
            processor, code, "", (char *)buf, decrypt_len);
    g_free(buf);
}
