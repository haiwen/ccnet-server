/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>


#include "keepalive-proc.h"

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

/* Since we use only tcp, packet should not be lost, MAX_NUM_RETRY set to 1,
   and set a large time (3min). */
#define KEEPALIVE_INTERVAL                180000 /* 3min */
#define MAX_NUM_RETRY                          1

#define MY_VERSION                             2

/* Select the version according to version used in the other peer.
 * -1 if v_other is not supported.
 */
static int get_used_version(int v_other)
{
    if (v_other != 2)
        return -1;
    return 2;
}

enum {
    INIT,
    WAIT_PUBKEY,
    WAIT_CHALLENGE,
    WAIT_KEEPALIVE,
    WAIT_PUBKEY_USER,
    WAIT_CHALLENGE_USER,
    FULL
};



/*
  protocol v1:
       state
                   keepalive v2
       INIT     -----------------> x (packet loss)

               <-----------------  start keepalive
                      OK v2

                     310
   WAIT_PUBKEY  ----------------->
   (optional)  <-----------------

                  311 random_buf
 WAIT_CHALLENGE ----------------->
               <-----------------


                     320
 WAIT_PUBKEY_USER  ----------------->
   (optional)  <-----------------

                  321 random_buf
 WAIT_CHALLENGE_USER ----------------->
               <-----------------

  
                  300  auth-state
 WAIT_KEEPALIVE -----------------> 
               <-----------------
                      OK

     FULL (keepalive interval)

                  300  auth-state
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
    int used_version;
    int count;
} CcnetKeepaliveProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_KEEPALIVE_PROC, CcnetKeepaliveProcPriv))

#define USE_PRIV CcnetKeepaliveProcPriv *priv = GET_PRIV (processor);


G_DEFINE_TYPE (CcnetKeepaliveProc, ccnet_keepalive_proc, CCNET_TYPE_PROCESSOR)


static int keepalive_start (CcnetProcessor *processor, 
                                int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void reset_timeout(CcnetProcessor *processor);
 
static void proc_shutdown (CcnetProcessor *processor)
{
    CcnetPeer *peer = processor->peer;

    if (IS_SLAVE(processor))
        return;

    if (peer->net_state == PEER_INDIRECT) {
        /* In indirect connection, we may receive SC_PROC_DEAD,
         * which cause shutdown be called.
         */
        /* detach from the peer */
        ccnet_peer_remove_processor (processor->peer, processor);
        ccnet_peer_shutdown (peer);
        peer->num_fails++;
    } else {
        /* Otherwise the shutdown of keepalive is only be called in
         * peer shutdown */
    }
}

static void
release_resource(CcnetProcessor *processor)
{
    processor->peer->keepalive_sending = 0;
    
    /* should always chain up */
    CCNET_PROCESSOR_CLASS(ccnet_keepalive_proc_parent_class)->release_resource (processor);
}

static void
ccnet_keepalive_proc_class_init (CcnetKeepaliveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "keepalive-proc";
    proc_class->start = keepalive_start;
    proc_class->handle_response = handle_response;
    proc_class->handle_update = handle_update;
    proc_class->shutdown = proc_shutdown;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof(CcnetKeepaliveProcPriv));
}

static void
ccnet_keepalive_proc_init (CcnetKeepaliveProc *processor)
{
}



static void send_keepalive(CcnetProcessor *processor)
{
    USE_PRIV;

    CcnetPeer *peer = processor->peer;
    CcnetUser *user = ccnet_peer_get_user(peer);

    GString *buf = g_string_new(NULL);
    GString *cntstr = g_string_new(NULL);

    g_string_append_printf(cntstr, "%d", priv->count++);

    g_string_append_printf (buf, "timestamp %"G_GINT64_FORMAT"\n",
                            processor->session->timestamp);
    if (user)
        g_string_append_printf (buf, "role-timestamp %"G_GINT64_FORMAT"\n",
                                user->myrole_timestamp);

    ccnet_processor_send_update (processor, "300", cntstr->str,
                                 buf->str, buf->len + 1);
    /* ccnet_debug ("[Keepalive] Send keepavlie to peer %.8s #%s\n", */
    /*              processor->peer->id, cntstr->str); */
    g_string_free (buf, TRUE);
    g_string_free (cntstr, TRUE);

    processor->state = WAIT_KEEPALIVE;
}

static void send_request(CcnetProcessor *processor)
{
    char buf[64];
    snprintf (buf, 64, "keepalive v%d", MY_VERSION);
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
    /* Since we set MAX_NUM_RETRY to 1, actually, there will be no retry. */
    if (processor->state == INIT) {
        if (++processor->num_retry < MAX_NUM_RETRY)
        {
            send_request(processor);
            return TRUE;
        } else {
            close_processor_in_timeout(processor);
            return FALSE;
        }
    }

    if (processor->state == WAIT_PUBKEY || processor->state == WAIT_CHALLENGE)
    {
        close_processor_in_timeout(processor);
        return FALSE;        
    }

    if (processor->state == WAIT_KEEPALIVE) {
        if (++processor->num_retry < MAX_NUM_RETRY) {
            send_keepalive (processor);
            return TRUE;
        } else {
            close_processor_in_timeout(processor);
            return FALSE;
        }
    }

    if (processor->state == FULL) {
        processor->num_retry = 0;
        send_keepalive(processor);
        return TRUE;
    }

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


static int keepalive_start (CcnetProcessor *processor, 
                            int argc, char **argv)
{
    CcnetKeepaliveProcPriv *priv = GET_PRIV (processor);

    if (IS_SLAVE(processor)) {
        char buf[16];
        int v, len;

        if (argc == 0) {
            priv->used_version = 0;
            ccnet_processor_send_response (processor,
                  SC_VERSION_MISMATCH, SS_VERSION_MISMATCH, NULL, 0);
            ccnet_processor_done (processor, FALSE);
            return 0;
        } else {
            v = get_version(argv[0]);
            if ((priv->used_version = get_used_version(v)) == -1) {
                ccnet_processor_send_response (processor,
                  SC_VERSION_MISMATCH, SS_VERSION_MISMATCH, NULL, 0);
                ccnet_processor_done (processor, FALSE);
                return 0;
            }

            len = snprintf (buf, 16, "v%d", priv->used_version);
            ccnet_processor_send_response (processor, 
                                    SC_OK, SS_OK, buf, len + 1);
            return 0;
        }
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

static void recv_pubkey_user(CcnetProcessor *processor, 
                             char *code, char *code_msg,
                             char *content, int clen);

static void verify_challenge_user(CcnetProcessor *processor, 
                                  char *code, char *code_msg,
                                  char *content, int clen);

static struct Handler rsp_handler_tab[] = {
    { "200", recv_ok }, 
    { "300", recv_keepalive_rsp },
    { "310", recv_pubkey },
    { "311", verify_challenge },
    { "320", recv_pubkey_user },
    { "321", verify_challenge_user },
    { 0 },
};

static void send_challenge(CcnetProcessor *processor)
{
    CcnetKeepaliveProcPriv *priv = GET_PRIV (processor);
    
    ccnet_debug ("[Keepalive] Send peer challenge to %s(%.8s)\n",
                 processor->peer->name, processor->peer->id);

    CcnetPeer *peer = processor->peer;
    unsigned char *buf;
    int len;

    RAND_pseudo_bytes (priv->random_buf, 40);
    buf = public_key_encrypt (peer->pubkey, priv->random_buf, 40, &len);
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

static void get_pubkey_user(CcnetProcessor *processor)
{
    ccnet_processor_send_update (processor,
                                 "320", NULL, NULL, 0);
    processor->state = WAIT_PUBKEY_USER;
    reset_timeout(processor);
}

static void send_challenge_user(CcnetProcessor *processor, CcnetUser *user)
{
    CcnetKeepaliveProcPriv *priv = GET_PRIV (processor);
    unsigned char *buf;
    int len;

    ccnet_debug ("[Keepalive] Send user challenge to %.8s\n",
                 processor->peer->id);
    RAND_pseudo_bytes (priv->random_buf, 40);
    buf = public_key_encrypt (user->pubkey, priv->random_buf, 40, &len);
    ccnet_processor_send_update (processor, "321", NULL, (char *)buf, len);

    g_free(buf);
    processor->state = WAIT_CHALLENGE_USER;
    reset_timeout (processor);
}


static void recv_ok(CcnetProcessor *processor, 
                    char *code, char *code_msg,
                    char *content, int clen)
{
    USE_PRIV;

    if (processor->state != INIT) {
        close_processor(processor);
        return;
    }

    /* check version */
    if (clen != 0) {
        int v = get_version(content);
        if ((priv->used_version = get_used_version(v)) == -1) {
            ccnet_processor_send_error_update(processor, SC_VERSION_MISMATCH,
                                              SS_VERSION_MISMATCH);
            close_processor(processor);
            return;
        }
    } else {
        ccnet_processor_send_error_update(processor, SC_VERSION_MISMATCH,
                                          SS_VERSION_MISMATCH);
        close_processor(processor);
        return;
    }

    if (processor->peer->net_state == PEER_DOWN)
        ccnet_peer_set_net_state (processor->peer, PEER_INDIRECT);
    
    if (processor->peer->pubkey)
        send_challenge(processor);
    else
        get_pubkey(processor);
}

static void recv_pubkey(CcnetProcessor *processor, 
                        char *code, char *code_msg,
                        char *content, int clen)
{
    if (clen == 0 || content[clen-1] != '\0') {
        ccnet_debug ("[Conn] Bad public key format\n");
        close_processor (processor);
        return;
    }

    ccnet_peer_set_pubkey (processor->peer, content);
    if (processor->peer->pubkey == NULL) {
        ccnet_debug ("[Conn] Bad public key format\n");
        close_processor (processor);
        return;
    }

    send_challenge (processor);
}
    
static void recv_keepalive_rsp(CcnetProcessor *processor, 
                               char *code, char *code_msg,
                               char *content, int clen)
{
    /* ccnet_debug ("[Keepalive] Receive keepalive responese from peer %.8s #%s\n", */
    /*              processor->peer->id, code_msg); */
    processor->state = FULL;
    if (processor->peer->net_state == PEER_CONNECTED
        && processor->peer->num_fails > 0)
        processor->peer->num_fails--;
}

static void verify_challenge(CcnetProcessor *processor, 
                             char *code, char *code_msg,
                             char *content, int clen)
{
    CcnetKeepaliveProcPriv *priv = GET_PRIV (processor);
    ccnet_debug ("[Conn] Verify Peer Challenge\n");

    if (clen != 40 || memcmp(content, priv->random_buf, 40) != 0) {
        ccnet_debug ("[Conn] Peer Challenge failed\n");
        close_processor(processor);
        return;
    }

    CcnetUser *user = ccnet_peer_get_user(processor->peer);
    if (!user) {
        ccnet_debug ("[Conn] No user for this peer, go to auth done\n");
        processor->peer->auth_done = 1;
        g_signal_emit_by_name (processor->peer, "auth-done");
        
        send_keepalive (processor);
        reset_timeout (processor);
        return;
    }

    if (user->pubkey)
        send_challenge_user(processor, user);
    else
        get_pubkey_user(processor);
}

static void recv_pubkey_user(CcnetProcessor *processor, 
                             char *code, char *code_msg,
                             char *content, int clen)
{
    if (clen == 0 || content[clen-1] != '\0') {
        ccnet_debug ("[Conn] Bad public key format\n");
        close_processor (processor);
        return;
    }

    CcnetUser *user = ccnet_peer_get_user(processor->peer);
    ccnet_user_set_pubkey (user, content);

    if (user->pubkey == NULL) {
        ccnet_debug ("[Conn] Bad public key format\n");
        close_processor (processor);
        return;
    }

    send_challenge_user (processor, user);
}

static void verify_challenge_user(CcnetProcessor *processor, 
                                  char *code, char *code_msg,
                                  char *content, int clen)
{
    CcnetKeepaliveProcPriv *priv = GET_PRIV (processor);
    ccnet_debug ("[Conn] Verify User Challenge\n");

    if (clen != 40 || memcmp(content, priv->random_buf, 40) != 0) {
        ccnet_debug ("[Keepalive] Challenge failed\n");
        close_processor(processor);
        return;
    }

    processor->peer->auth_done = 1;
    g_signal_emit_by_name (processor->peer, "auth-done");

    send_keepalive (processor);
    reset_timeout (processor);
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

/*
static void start_keepalive (CcnetProcFactory *factory, CcnetPeer *peer)
{
    CcnetProcessor *processor;
    
    processor = ccnet_proc_factory_create_master_processor (
        factory, "keepalive", peer);

    if (processor == NULL) {
        ccnet_warning ("Create keepalive processor failed\n");
        return;
    }
    ccnet_processor_startl (processor, NULL);
}
*/


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

static void send_pubkey_user(CcnetProcessor *processor, 
                             char *code, char *code_msg,
                             char *content, int clen);

static void response_challenge_user(CcnetProcessor *processor, 
                                    char *code, char *code_msg,
                                    char *content, int clen);

static struct Handler update_handler_tab[] = {
    { "300", receive_keepalive },
    { "310", send_pubkey },
    { "311", response_challenge },
    { "320", send_pubkey_user },
    { "321", response_challenge_user },
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


static void get_user_pubinfo (CcnetPeer *peer)
{
    CcnetProcessor *newp;
    CcnetProcFactory *factory = peer->manager->session->proc_factory;
    
    newp = ccnet_proc_factory_create_master_processor (factory,
                                          "get-user", peer);
    if (newp == NULL) {
        ccnet_warning ("Create get user info processor failed\n");
        return;
    }
    ccnet_processor_startl (newp, NULL);
}


static void update_from_key_value (void *vpeer,
                                   const char *key,
                                   const char *value)
{
    CcnetPeer *peer = vpeer;

    if (strcmp(key, "timestamp") == 0) {
        gint64 timestamp = g_ascii_strtoll(value, NULL, 10);
        if (timestamp > peer->timestamp)
            get_peer_pubinfo (peer);
        CcnetUser *user = ccnet_peer_get_user(peer);
        if (!user || timestamp > user->timestamp)
            get_user_pubinfo (peer);
    }

    if (strcmp(key, "role-timestamp") == 0) {
        CcnetUser *user = ccnet_peer_get_user(peer);
        if (!user)
            return;
        gint64 timestamp = g_ascii_strtoll (value, NULL, 10);
        if (timestamp < user->role_timestamp) {
            ccnet_peer_manager_notify_peer_role (peer->manager, peer);
        }
    }
}


static void receive_keepalive(CcnetProcessor *processor, 
                              char *code, char *code_msg,
                              char *content, int clen)
{
    CcnetPeer *peer = processor->peer;

    if (clen == 0 || content[clen-1] != '\0' || content[clen-2] != '\n')
    {
        ccnet_processor_send_response (
            processor, SC_BAD_KEEPALIVE, SS_BAD_KEEPALIVE, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    parse_key_value_pairs (content, update_from_key_value, peer);

    /* ccnet_debug ("[Keepalive] Receive keepalive from %.8s #%s\n", */
    /*              processor->peer->id, code_msg); */
    ccnet_processor_send_response (
        processor, code, code_msg, NULL, 0);

    /* Peer discovered us, so we try to discover peer too.
     * Used in indirect connection vie Relay */
    /*
    if (peer->net_state == PEER_DOWN && peer->relay_list != NULL) {
        if (!peer->keepalive_sending)
            start_keepalive (processor->session->proc_factory, peer);
    }
    */
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

static void send_pubkey_user(CcnetProcessor *processor, 
                             char *code, char *code_msg,
                             char *content, int clen)
{
    GString *str;
    
    str = public_key_to_gstring(processor->session->user_pubkey);
    ccnet_processor_send_response (processor, code, "", str->str, str->len+1);
}

static void response_challenge_user(CcnetProcessor *processor, 
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
        
    buf = private_key_decrypt(processor->session->user_privkey,
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
