/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include "rcvcmd-proc.h"

#include "peer.h"
#include "session.h"
#include "peer-mgr.h"
#include "connect-mgr.h"
#include "proc-factory.h"
#include "message.h"
#include "message-manager.h"

#include "algorithms.h"
#include "utils.h"
#include "net.h"
#include "log.h"

#ifdef CCNET_CLUSTER
  #include "cluster-mgr.h"
#endif
#ifdef CCNET_DAEMON
  #include "daemon-session.h"
#endif


#define SC_UNKNONW_CMD "400"
#define SS_UNKNONW_CMD "Unknown Command"
#define SC_BAD_PACKET_FMT "401"
#define SS_BAD_PACKET_FMT "Bad Packet Format"
#define SC_BAD_CMD_FMT "402"
#define SS_BAD_CMD_FMT "Bad Command Format"
#define SC_NO_MSG "403"
#define SS_NO_MSG "Message Not Exist"
#define SC_NO_PEER "410"
#define SS_NO_PEER "No Such Peer"
#define SC_NO_PROCESSOR "411"
#define SS_NO_PROCESSOR "No Such Processor"
#define SC_NO_USER "413"
#define SS_NO_USER "No Such User"
#define SC_NO_GROUP "430"
#define SS_NO_GROUP "No Such Group"

#define PARSE_OPTIONS                                               \
    do {                                                            \
    context = g_option_context_new (NULL);                          \
    g_option_context_add_main_entries (context, cmd_entries, NULL); \
    if (!g_option_context_parse (context, &argc, &argv, &error)) {  \
        g_print ("option parsing failed: %s\n", error->message);    \
        return -1;                                                  \
    }                                                               \
    } while (0)

enum {
    INIT
};

typedef struct  {
    int    persist : 1;
} CcnetRcvcmdProcPriv;

#define GET_PRIV(o)                                                     \
    (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_RCVCMD_PROC, CcnetRcvcmdProcPriv))


static int rcv_cmd_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor, 
                           char *code, char *code_msg,
                           char *content, int clen);


G_DEFINE_TYPE (CcnetRcvcmdProc, ccnet_rcvcmd_proc, CCNET_TYPE_PROCESSOR)

static void
ccnet_rcvcmd_proc_class_init (CcnetRcvcmdProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "rcvcmd-proc";
    proc_class->start = rcv_cmd_start;
    proc_class->handle_update = handle_update;

    g_type_class_add_private (klass, sizeof (CcnetRcvcmdProcPriv));
}

static void
ccnet_rcvcmd_proc_init (CcnetRcvcmdProc *processor)
{
}


static int rcv_cmd_start (CcnetProcessor *processor, int argc, char **argv)
{
    CcnetRcvcmdProcPriv *priv = GET_PRIV (processor);

    priv->persist = 0;

    while (0 < argc && argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'p':
            priv->persist = 1;
            break;
        default:
            break;
        }
        argc--; argv++;
    }

    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
    return 0;
}

struct cmd
{
    char *name;
    int (*handler) (CcnetProcessor *, int argc, char **argv);
};

static int shutdown_session (CcnetProcessor *, int, char **);
static int register_service (CcnetProcessor *, int, char **);
static int echo (CcnetProcessor *, int, char **);
static int list_proc (CcnetProcessor *, int, char **);
static int set_timeout (CcnetProcessor *, int, char **);

static int add_role  (CcnetProcessor *, int, char **);
static int set_addr  (CcnetProcessor *, int, char **);
static int add_peer    (CcnetProcessor *, int, char **);
static int delete_peer (CcnetProcessor *, int, char **);
static int delete_role (CcnetProcessor *, int, char **);
static int connect_peer           (CcnetProcessor *, int, char **);
static int disconnect_peer        (CcnetProcessor *, int, char **);
static int conn_cancel (CcnetProcessor *, int, char **);
static int invoke_echo (CcnetProcessor *, int, char **);


#ifdef CCNET_CLUSTER
static int add_member    (CcnetProcessor *, int, char **);
static int add_master    (CcnetProcessor *, int, char **);
static int redirect_peer (CcnetProcessor *, int, char **);
#endif

#ifdef CCNET_DAEMON
static int add_relay (CcnetProcessor *, int, char **);
#endif


static struct cmd cmdtab[] =  {
    { "shutdown",     shutdown_session },
    { "register-service", register_service },
    { "echo", echo },
	{ "list-proc", list_proc },
    { "set-timeout", set_timeout },
    { "add-role", add_role },
    { "add-peer", add_peer },
    { "del-peer", delete_peer },
    { "del-role", delete_role },
    { "set-addr", set_addr },
#ifdef CCNET_DAEMON
    { "add-relay", add_relay },
#endif
#ifdef CCNET_CLUSTER
    { "add-member",  add_member },
    { "add-master",  add_master },
    { "redirect-peer", redirect_peer },
#endif
    /* { "group-create", create_group }, */
    /* { "group-follow", follow_group }, */
    /* { "group-unfollow", unfollow_group }, */
    /* { "group-show", show_group }, */
    /* { "group-add-member", add_group_member  }, */
    /* { "group-del-member", delete_group_member  }, */
    /* { "group-del-follower", delete_group_follower  }, */
    /* { "group-add-maintainer", add_group_maintainer  }, */
    { "connect", connect_peer },
    { "disconnect", disconnect_peer },
    { "conn-cancel", conn_cancel },
    { "invoke-echo", invoke_echo },
    { 0 },
};

struct cmd *
getcmd (char *name)
{
    char *p, *q;
    struct cmd *c, *found;
    int nmatches, longest;

    longest = 0;
    nmatches = 0;
    found = 0;
    for (c = cmdtab; (p = c->name); c++) {
        for (q = name; *q == *p++; q++)
            if (*q == 0)		/* exact match? */
                return c;
        if (!*q) {	/* the name was a prefix */
            if (q - name > longest) {
                longest = q - name;
                nmatches = 1;
                found = c;
            } else if (q - name == longest)
                nmatches++;
        }
    }
  
    if (nmatches > 1)
        return (struct cmd *)-1;
    return found;
}


static void handle_command (CcnetProcessor *processor, char *line)
{
    gchar **commands;
    gchar **pcmd;
    struct cmd *c;
    int i;

    commands = g_strsplit_set (line, " \t", 10);
    for (i = 0, pcmd = commands; *pcmd; pcmd++)
        i++;
    
    if (i == 0) {
        g_strfreev (commands);
        return;
    }

    /* puts (commands[0]); */
    c = getcmd (commands[0]);
    if (c == NULL) {
        ccnet_processor_send_response (processor, SC_UNKNONW_CMD, 
                                       SS_UNKNONW_CMD, NULL, 0);
    } else
        c->handler (processor, i, commands);

    g_strfreev (commands);
}


static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    CcnetRcvcmdProcPriv *priv = GET_PRIV (processor);

    if (content[clen-1] != '\0') {
        ccnet_processor_send_response (processor, SC_BAD_PACKET_FMT, 
                                       SS_BAD_PACKET_FMT, NULL, 0);
        if (!priv->persist)
            ccnet_processor_done (processor, FALSE);
        return;
    }
    
    handle_command (processor, content);
    if (!priv->persist)
        ccnet_processor_done (processor, TRUE);
}

int shutdown_session (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    ccnet_processor_send_response (processor, SC_OK, NULL, NULL, 0);

    ccnet_session_on_exit (processor->session);

    exit (0);

    return 0;
}


static int register_service (CcnetProcessor *processor, 
                             int argc, char **argv)
{
    argc--;
    argv++;

    int ret = 0;
    char *group = "inner";
    if (argc < 1) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }
    if (argc >= 2)
        group = argv[1];
    ret = ccnet_session_register_service (processor->session,
                                          argv[0], group,
                                          processor->peer);

    if (ret < 0)
        ccnet_processor_send_response (processor, SC_SERV_EXISTED,
                                       SS_SERV_EXISTED, NULL, 0);
    else
        ccnet_processor_send_response (processor, SC_OK,
                                       NULL, NULL, 0);
    return 0;
}


static int echo (CcnetProcessor *processor, 
                 int argc, char **argv)
{
    argc--;
    argv++;

    if (argc == 1) {
        ccnet_processor_send_response (processor, SC_OK, "", 
                                       argv[0], strlen(argv[0])+1);

    } else {
        ccnet_processor_send_response (processor, SC_OK, "",
                                       "Hello", strlen("Hello")+1);
    }

    return 0;
}

static int
list_proc (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    CcnetPeerManager *peerMgr;
    CcnetPeer *peer;
    CcnetProcessor *proc;
    GList *peerlist, *peeriter;
    GList *proclist, *prociter;
    GString *buf = g_string_new (NULL);
    
    peerMgr = processor->session->peer_mgr;
    peerlist = ccnet_peer_manager_get_peer_list (peerMgr);
    
    for (peeriter=peerlist; peeriter; peeriter=peeriter->next) {
        peer = (CcnetPeer *)(peeriter->data);
        proclist = g_hash_table_get_values (peer->processors);
        
        for (prociter=proclist; prociter; prociter = prociter->next) {
            proc = (CcnetProcessor *)(prociter->data);
            g_string_append_printf (buf, "%d\t%s\n", PRINT_ID(proc->id),
                                    GET_PNAME(proc));
        }

        g_list_free (proclist);
    }
    g_list_free (peerlist);

    ccnet_processor_send_response (processor, SC_OK, SS_OK, 
                                   buf->str, buf->len);
    
    g_string_free (buf, TRUE);
    
    return 0;
}

static int 
set_timeout (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    if (argc < 2) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }

    if (strcmp("proc-keepalive-timeout", argv[0]) == 0) {
        ccnet_proc_factory_set_keepalive_timeout (
            processor->session->proc_factory, atoi(argv[1]));
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        return 0;
    }

    ccnet_processor_send_response (processor, "401", "No such timer", NULL, 0);
    return -1;
}


static int
set_addr (CcnetProcessor *processor, int argc, char **argv)
{
    CcnetPeerManager *mgr = processor->session->peer_mgr;
    CcnetPeer *peer;
    int port = DEFAULT_PORT;
    argc--;
    argv++;
    
    if (argc < 2) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }
    if (argc > 2) {
        port = atoi (argv[2]);
        if (port <= 0) {
            ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                           "Invalid port", NULL, 0);
            return -1;
        }
    }

    peer = ccnet_peer_manager_get_peer (mgr, argv[0]);
    if (!peer) {
        ccnet_processor_send_response (processor, "400",
                                       "Load peer error", NULL, 0);
        return -1;
    }

    ccnet_peer_manager_set_peer_public_addr (mgr, peer, argv[1], port);
    ccnet_processor_send_response (processor, SC_OK, SS_OK,
                                   peer->id, 41);
    g_object_unref (peer);
    return 0;
}

#ifdef CCNET_DAEMON

/* add-relay [--id <peer-id>] [--addr <peer-addr:port>]
 */
static int
add_relay (CcnetProcessor *processor, int argc, char **argv)
{
    CcnetPeerManager *mgr = processor->session->peer_mgr;
    CcnetPeer *peer = NULL;
    char *peer_id = NULL;
    char *addr_port = NULL;
    char *role = NULL;
    char *addr;
    uint16_t port;
    int ret;

    GOptionContext *context;
    GError *error = NULL;
    GOptionEntry cmd_entries[] = {
        { .long_name            = "id",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &peer_id, 
          .description          = "the peer id",
          .arg_description      = NULL },
        { .long_name            = "addr",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &addr_port,
          .description          = "the address and port of the peer",
          .arg_description      = NULL },
        { NULL },
    };

    PARSE_OPTIONS;

    /* check addr_port and peer id */
    if (addr_port) {
        addr = addr_port;
        char *p;
        if ( (p = strchr(addr_port, ':')) == NULL) {
            port = DEFAULT_PORT;
        } else {
            *p = '\0';
            port = atoi(p+1);
            if (port == 0) {
                 ccnet_processor_send_response (
                     processor, "400", "Invalid Address", NULL, 0);
                 ret = -1;
                 goto out;
            }
        }
    }

    if (peer_id) {
        if (!peer_id_valid(peer_id)) {
            ccnet_processor_send_response (
                processor, "400", "Invalid Peer ID", NULL, 0);
            ret = -1;
            goto out;
        }
    }

    if (addr_port && peer_id) {
        peer = ccnet_peer_manager_get_peer (mgr, peer_id);
        if (!peer) {
            ccnet_message("Add server %.8s %s:%d\n", peer_id, addr, port);
            peer = ccnet_peer_new (peer_id);
            ccnet_peer_manager_add_peer (mgr, peer);
            ccnet_peer_manager_set_peer_public_addr (mgr, peer, addr, port);
            ccnet_peer_manager_add_role (mgr, peer, "MyRelay");
            ccnet_conn_manager_connect_peer (processor->session->connMgr, peer);
        }

        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        ret = 0;
        goto out;
    }

    /* only addr */
    if (addr_port) {
        peer = ccnet_peer_manager_add_resolve_peer (
            processor->session->peer_mgr, addr, port);
        peer->want_tobe_relay = 1;
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        ret = 0;
        goto out;
    }

    /* only id */
    if (peer_id) {
        peer = ccnet_peer_manager_get_peer (mgr, peer_id);
        if (!peer) {
            peer = ccnet_peer_new (peer_id);
            ccnet_peer_manager_add_peer (mgr, peer);
        }

        ccnet_peer_manager_add_role (mgr, peer, "MyRelay");
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        ret = 0;
        goto out;
    }

    ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                   SS_BAD_CMD_FMT, NULL, 0);
    ret = -1;

out:
    g_free (addr_port);
    g_free (role);
    g_free (peer_id);
    if (peer) g_object_unref (peer);
    return ret;
}


#endif


static int
add_role (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    CcnetPeerManager *mgr = processor->session->peer_mgr;
    CcnetPeer *peer;

    if (argc != 2) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }

    if (strlen(argv[0]) != 40) {
        ccnet_processor_send_response (processor, "400",
                                       "Peer id must be of length 40", NULL, 0);
        return -1;
    }

    peer = ccnet_peer_manager_get_peer (mgr, argv[0]);
    if (!peer) {
        ccnet_processor_send_response (processor, SC_NO_PEER,
                                       SS_NO_PEER, NULL, 0);
        return -1;
    }

    ccnet_peer_manager_add_role (mgr, peer, argv[1]);
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    g_object_unref (peer);
    return 0;
}


static int
delete_role (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    CcnetPeerManager *mgr = processor->session->peer_mgr;
    CcnetPeer *peer;

    if (argc != 2) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }

    if (strlen(argv[0]) != 40) {
        ccnet_processor_send_response (processor, "400",
                                       "Peer id must be of length 40", NULL, 0);
        return -1;
    }

    peer = ccnet_peer_manager_get_peer (mgr, argv[0]);
    if (!peer) {
        ccnet_processor_send_response (processor, SC_NO_PEER,
                                       SS_NO_PEER, NULL, 0);
        return -1;
    }
    
    ccnet_peer_manager_remove_role (mgr, peer, argv[1]);
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    g_object_unref (peer);
    return 0;
} 


/* add-peer [--id <peer-id>] [--addr <peer-addr:port>] [--role <role>]
 */
static int
add_peer (CcnetProcessor *processor, int argc, char **argv)
{
    CcnetPeerManager *mgr = processor->session->peer_mgr;
    CcnetPeer *peer = NULL;
    char *peer_id = NULL;
    char *addr_port = NULL;
    char *role = NULL;
    char *addr;
    uint16_t port;
    int ret;

    GOptionContext *context;
    GError *error = NULL;
    GOptionEntry cmd_entries[] = {
        { .long_name            = "id",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &peer_id, 
          .description          = "the peer id",
          .arg_description      = NULL },
        { .long_name            = "addr",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &addr_port,
          .description          = "the address and port of the peer",
          .arg_description      = NULL },
        { .long_name            = "role",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &role,
          .description          = "the role of the peer",
          .arg_description      = NULL },
        { NULL },
    };

    PARSE_OPTIONS;

    /* check addr_port and peer id */
    if (addr_port) {
        addr = addr_port;
        char *p;
        if ( (p = strchr(addr_port, ':')) == NULL) {
            port = DEFAULT_PORT;
        } else {
            *p = '\0';
            port = atoi(p+1);
            if (port == 0) {
                 ccnet_processor_send_response (
                     processor, "400", "Invalid Address", NULL, 0);
                 ret = -1;
                 goto out;
            }
        }
    }

    if (peer_id) {
        if (!peer_id_valid(peer_id)) {
            ccnet_processor_send_response (
                processor, "400", "Invalid Peer ID", NULL, 0);
            ret = -1;
            goto out;
        }
    }

    if (addr_port && peer_id) {
        peer = ccnet_peer_manager_get_peer (mgr, peer_id);
        if (!peer) {
            peer = ccnet_peer_new (peer_id);
            ccnet_peer_manager_add_peer (mgr, peer);
        }

        ccnet_peer_manager_set_peer_public_addr (mgr, peer, addr, port);
        if (role)
            ccnet_peer_manager_add_role (mgr, peer, role);
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        ret = 0;
        goto out;
    }

    /* only addr */
    if (addr_port) {
        peer = ccnet_peer_manager_add_resolve_peer (
            processor->session->peer_mgr, addr, port);
        g_free (peer->intend_role);
        peer->intend_role = g_strdup(role);
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        ret = 0;
        goto out;
    }

    /* only id */
    if (peer_id) {
        peer = ccnet_peer_manager_get_peer (mgr, peer_id);
        if (peer) {
            ret = 0;
            goto out;
        }

        peer = ccnet_peer_new (peer_id);
        ccnet_peer_manager_add_peer (mgr, peer);
        if (role)
            ccnet_peer_manager_add_role (mgr, peer, role);
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        ret = 0;
        goto out;
    }

    ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                   SS_BAD_CMD_FMT, NULL, 0);
    ret = -1;

out:
    g_free (addr_port);
    g_free (role);
    g_free (peer_id);
    if (peer) g_object_unref (peer);
    return ret;
}


static int
delete_peer (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    CcnetPeerManager *mgr = processor->session->peer_mgr;
    CcnetPeer *peer;

    if (argc < 1) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }

    if (strlen(argv[0]) != 40) {
        ccnet_processor_send_response (processor, "400",
                                       "Peer id must be of length 40", NULL, 0);
        return -1;
    }

    peer = ccnet_peer_manager_get_peer (mgr, argv[0]);
    if (peer) {
        ccnet_peer_manager_remove_peer (mgr, peer);
        g_object_unref (peer);
    }
    
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
    return 0;
}


static int
connect_peer (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    CcnetPeerManager *mgr = processor->session->peer_mgr;
    char *peer_id;
    CcnetPeer *peer;

    if (argc != 1) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }

    if (strlen(argv[0]) != 40) {
        ccnet_processor_send_response (processor, "400",
                                       "Peer id must be of length 40", NULL, 0);
        return -1;
    }
    peer_id = argv[0];

    peer = ccnet_peer_manager_get_peer (mgr, peer_id);
    if (!peer) {
        ccnet_processor_send_response (
            processor, "400", "Can not find peer", NULL, 0);
        return -1;
    }

    ccnet_conn_manager_add_to_conn_list (processor->session->connMgr, peer);
    ccnet_conn_manager_connect_peer (processor->session->connMgr, peer);
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    g_object_unref (peer);
    return 0;
}

static int
disconnect_peer (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    CcnetPeerManager *mgr = processor->session->peer_mgr;
    char *peer_id;
    CcnetPeer *peer;

    if (argc != 1) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }

    if (strlen(argv[0]) != 40) {
        ccnet_processor_send_response (processor, "400",
                                       "Peer id must be of length 40", NULL, 0);
        return -1;
    }
    peer_id = argv[0];

    peer = ccnet_peer_manager_get_peer (mgr, peer_id);
    if (!peer) {
        ccnet_processor_send_response (
            processor, "400", "Can not find peer", NULL, 0);
        return -1;
    }

    ccnet_conn_manager_remove_from_conn_list (processor->session->connMgr,
                                              peer);
    ccnet_peer_shutdown (peer);
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    g_object_unref (peer);
    return 0;
}


static int
conn_cancel (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    if (argc != 2) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }

    int port = atoi(argv[1]);

    ccnet_conn_manager_cancel_conn (processor->session->connMgr, argv[0], port);
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    return 0;
}


static int
invoke_echo (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    CcnetPeerManager *mgr = processor->session->peer_mgr;
    CcnetPeer *peer;

    if (argc != 1) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }

    if (!peer_id_valid(argv[0])) {
        ccnet_processor_send_response (processor, "400",
                                       "Invalid peer id", NULL, 0);
        return -1;
    }

    peer = ccnet_peer_manager_get_peer (mgr, argv[0]);
    if (!peer) {
        ccnet_processor_send_response (
            processor, "400", "Can not find peer", NULL, 0);
        return -1;
    }
    CcnetProcessor *proc;
    proc = ccnet_proc_factory_create_master_processor (
        processor->session->proc_factory, "echo", peer);
    ccnet_processor_start (proc, 0, NULL);
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    g_object_unref (peer);
    return 0;
}


#ifdef CCNET_CLUSTER

extern CcnetClusterManager *cluster_mgr;

/* add-member [--id <peer-id>]
 */
static int
add_member (CcnetProcessor *processor, int argc, char **argv)
{
    CcnetPeerManager *mgr = processor->session->peer_mgr;
    CcnetPeer *peer = NULL;
    char *peer_id = NULL;
    char *addr_port = NULL;
    char *addr;
    uint16_t port;
    int ret;

    GOptionContext *context;
    GError *error = NULL;
    GOptionEntry cmd_entries[] = {
        { .long_name            = "id",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &peer_id, 
          .description          = "the peer id",
          .arg_description      = NULL },
        { .long_name            = "addr",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &addr_port,
          .description          = "the address and port of the peer",
          .arg_description      = NULL },
        { NULL },
    };

    PARSE_OPTIONS;


    if (!peer_id) {
        ccnet_processor_send_response (
            processor, "400", "Must specify Peer ID", NULL, 0);
        ret = -1;
        goto out;
    }

    if (!peer_id_valid(peer_id)) {
        ccnet_processor_send_response (
            processor, "400", "Invalid Peer ID", NULL, 0);
        ret = -1;
        goto out;
    }

    /* check addr_port and peer id */
    if (addr_port) {
        addr = addr_port;
        char *p;
        if ( (p = strchr(addr_port, ':')) == NULL) {
            port = DEFAULT_PORT;
        } else {
            *p = '\0';
            port = atoi(p+1);
            if (port == 0) {
                 ccnet_processor_send_response (
                     processor, "400", "Invalid Address", NULL, 0);
                 ret = -1;
                 goto out;
            }
        }
    }

    peer = ccnet_peer_manager_get_peer (mgr, peer_id);
    if (!peer) {
        peer = ccnet_peer_new (peer_id);
        ccnet_peer_manager_add_peer (mgr, peer);
    }
    if (addr)
        ccnet_peer_manager_set_peer_public_addr (mgr, peer, addr, port);

    ccnet_peer_manager_add_role (mgr, peer, "ClusterMember");
    ccnet_cluster_manager_add_member (cluster_mgr, peer);

    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
    ret = 0;
    goto out;

out:
    g_free (peer_id);
    if (peer) g_object_unref (peer);
    return ret;
}

/* add-master [--id <peer-id>] [--addr <ip:port>]
 */
static int
add_master (CcnetProcessor *processor, int argc, char **argv)
{
    CcnetPeerManager *mgr = processor->session->peer_mgr;
    CcnetPeer *peer = NULL;
    char *peer_id = NULL;
    char *addr_port = NULL;
    char *addr;
    uint16_t port;
    int ret;

    GOptionContext *context;
    GError *error = NULL;
    GOptionEntry cmd_entries[] = {
        { .long_name            = "id",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &peer_id, 
          .description          = "the peer id",
          .arg_description      = NULL },
        { .long_name            = "addr",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &addr_port,
          .description          = "the address and port of the peer",
          .arg_description      = NULL },
        { NULL },
    };

    PARSE_OPTIONS;


    if (!peer_id) {
        ccnet_processor_send_response (
            processor, "400", "Must specify Peer ID", NULL, 0);
        ret = -1;
        goto out;
    }

    if (!peer_id_valid(peer_id)) {
        ccnet_processor_send_response (
            processor, "400", "Invalid Peer ID", NULL, 0);
        ret = -1;
        goto out;
    }

    /* check addr_port and peer id */
    if (addr_port) {
        addr = addr_port;
        char *p;
        if ( (p = strchr(addr_port, ':')) == NULL) {
            port = DEFAULT_PORT;
        } else {
            *p = '\0';
            port = atoi(p+1);
            if (port == 0) {
                 ccnet_processor_send_response (
                     processor, "400", "Invalid Address", NULL, 0);
                 ret = -1;
                 goto out;
            }
        }
    }

    peer = ccnet_peer_manager_get_peer (mgr, peer_id);
    if (!peer) {
        peer = ccnet_peer_new (peer_id);
        ccnet_peer_manager_add_peer (mgr, peer);
    }

    if (addr)
        ccnet_peer_manager_set_peer_public_addr (mgr, peer, addr, port);

    ccnet_peer_manager_add_role (mgr, peer, "ClusterMaster");
    ccnet_cluster_manager_add_master (cluster_mgr, peer);
    
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
    ret = 0;
    goto out;

out:
    g_free (addr);
    g_free (peer_id);
    if (peer) g_object_unref (peer);
    return ret;
}

static int
redirect_peer (CcnetProcessor *processor, int argc, char **argv)
{
    argc--;
    argv++;

    CcnetPeerManager *mgr = processor->session->peer_mgr;
    char *peer_id, *to_id;
    CcnetPeer *peer, *to;

    if (argc != 2) {
        ccnet_processor_send_response (processor, SC_BAD_CMD_FMT,
                                       SS_BAD_CMD_FMT, NULL, 0);
        return -1;
    }

    if (!peer_id_valid(argv[0]) || !peer_id_valid(argv[1])) {
        ccnet_processor_send_response (processor, "400",
                                       "Invalid peer id", NULL, 0);
        return -1;
    }

    peer_id = argv[0];
    to_id = argv[1];
    peer = ccnet_peer_manager_get_peer (mgr, peer_id);
    if (!peer) {
        ccnet_processor_send_response (
            processor, "400", "Can not find peer", NULL, 0);
        return -1;
    }
    to = ccnet_peer_manager_get_peer (mgr, to_id);
    if (!to) {
        g_object_unref (peer);
        ccnet_processor_send_response (
            processor, "400", "Can not redirect destination peer", NULL, 0);
        return -1;
    }

    ccnet_peer_manager_redirect_peer (mgr, peer, to);
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    g_object_unref (peer);
    g_object_unref (to);
    return 0;
}

#endif
