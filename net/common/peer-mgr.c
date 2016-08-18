/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <glib/gstdio.h>

#include "timer.h"
#include "ccnet-db.h"
#include "net.h"

#include "peer.h"
#include "session.h"
#include "ccnet-config.h"
#include "peer-mgr.h"
#include "peermgr-message.h"
#include "connect-mgr.h"

#include "algorithms.h"
#include "utils.h"

#ifdef CCNET_DAEMON
#include "daemon-session.h"
#endif

#define DEBUG_FLAG  CCNET_DEBUG_PEER
#include "log.h"

#define NOTIFY_MSEC    5000    /* 5s */
#define DEFAULT_NOTIFY_INTERVAL      86400 * 2

#define SAVING_INTERVAL_MSEC 10000
#define PEER_GC_TIMEOUT      3*60
#define PEERDB_NAME       "peer-db"

struct CcnetPeerManagerPriv {
    CcnetDB     *db;
    CcnetTimer  *timer;

    /* the list of peers to be resolved */
    GList       *resolve_peers;
};


enum {
    ADDED_SIG,
    DELETING_SIG,
    PEER_AUTH_DONE_SIG,
    LAST_SIGNAL
};

G_DEFINE_TYPE (CcnetPeerManager, ccnet_peer_manager, G_TYPE_OBJECT);

static guint signals[LAST_SIGNAL] = { 0 };

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_PEER_MANAGER, CcnetPeerManagerPriv))

/* static int notify_pulse (CcnetPeerManager *manager); */
static int open_db (CcnetPeerManager *manager);
static void save_peer_addr(CcnetPeerManager *manager, CcnetPeer *peer);
static void remove_peer_roles(CcnetPeerManager *manager, char *peer_id);
void ccnet_peer_manager_load_peerdb (CcnetPeerManager *manager);


static void
ccnet_peer_manager_class_init (CcnetPeerManagerClass *klass)
{
    signals[ADDED_SIG] = 
        g_signal_new ("peer-added", CCNET_TYPE_PEER_MANAGER, 
                      G_SIGNAL_RUN_LAST,
                      0,        /* no class singal handler */
                      NULL, NULL, /* no accumulator */
                      g_cclosure_marshal_VOID__POINTER,
                      G_TYPE_NONE, 1, G_TYPE_POINTER);

    signals[DELETING_SIG] = 
        g_signal_new ("peer-deleting", CCNET_TYPE_PEER_MANAGER, 
                      G_SIGNAL_RUN_LAST,
                      0,        /* no class singal handler */
                      NULL, NULL, /* no accumulator */
                      g_cclosure_marshal_VOID__POINTER,
                      G_TYPE_NONE, 1, G_TYPE_POINTER);

    signals[PEER_AUTH_DONE_SIG] = 
        g_signal_new ("peer-auth-done", CCNET_TYPE_PEER_MANAGER, 
                      G_SIGNAL_RUN_LAST,
                      0,        /* no class singal handler */
                      NULL, NULL, /* no accumulator */
                      g_cclosure_marshal_VOID__POINTER,
                      G_TYPE_NONE, 1, G_TYPE_POINTER);

    g_type_class_add_private (klass, sizeof (CcnetPeerManagerPriv));
}


static void
ccnet_peer_manager_init (CcnetPeerManager *manager)
{
    manager->priv = GET_PRIV (manager);
}


CcnetPeerManager*
ccnet_peer_manager_new (CcnetSession *session)
{
    CcnetPeerManager *manager;

    manager = g_object_new (CCNET_TYPE_PEER_MANAGER, NULL);

    manager->session = session;

    manager->peer_hash = g_hash_table_new (g_str_hash, g_str_equal);

    return manager;
}

int
ccnet_peer_manager_prepare (CcnetPeerManager *manager)
{
    CcnetPeer *peer;
    CcnetSession *session = manager->session;

    /* peer point to myself */
    peer = ccnet_peer_new (session->base.id);
    peer->name = (char *)session->base.name;
    peer->public_port = session->base.public_port;
    peer->port = session->base.public_port;
    peer->service_url = session->base.service_url;
    peer->pubkey = session->pubkey;
    /* set to -1 so it will not be saved in to_string() */
    peer->net_state = -1;
    peer->is_self = 1;
    peer->manager = manager;
    
    g_hash_table_insert (manager->peer_hash, peer->id, peer);
    session->myself = peer;

    return 0;
}

void
ccnet_peer_manager_free (CcnetPeerManager *manager)
{
    g_free (manager->peerdb_path);
    g_object_unref (manager);
}

GList *
ccnet_peer_manager_get_peer_list (CcnetPeerManager *manager)
{
    return g_hash_table_get_values (manager->peer_hash);
}

GList*
ccnet_peer_manager_get_peers_with_role (CcnetPeerManager *manager,
                                        const char *role)
{
    GHashTableIter iter;
    gpointer key, value;
    CcnetPeer *peer;
    GList *list = 0;

    g_hash_table_iter_init (&iter, manager->peer_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        peer = value;
        if (ccnet_peer_has_role(peer, role)) {
            list = g_list_prepend (list, peer);
            g_object_ref (peer);
        }
    }
    return list;
}


static void
add_peer (CcnetPeerManager *manager, CcnetPeer *peer)
{
    peer->manager = manager;

    g_object_ref (peer);
    g_hash_table_insert (manager->peer_hash, peer->id, peer);

    if (!peer->is_self) {
        g_signal_emit (manager, signals[ADDED_SIG], 0, peer);
    }
}

void
ccnet_peer_manager_add_peer (CcnetPeerManager *manager, CcnetPeer *peer)
{
    add_peer (manager, peer);
    peer->need_saving = 1;
}

static void
delete_peer(CcnetPeerManager *manager, CcnetPeer *peer)
{
    char *path;

    /* delete peer conf file from peer-db */
    path = g_build_filename(manager->peerdb_path, peer->id, NULL);

    if (g_unlink(path) < 0)
        ccnet_warning("delete file %s error\n", path);

    g_hash_table_remove (manager->peer_hash, peer->id);
    remove_peer_roles (manager, peer->id);
    g_signal_emit (manager, signals[DELETING_SIG], 0, peer);

    g_object_unref (peer);
    g_free(path);
}

void
ccnet_peer_manager_remove_peer (CcnetPeerManager *manager,
                                CcnetPeer *peer)
{
    ccnet_peer_shutdown (peer);
    delete_peer(manager, peer);
}

CcnetPeer *
ccnet_peer_manager_add_resolve_peer (CcnetPeerManager *manager,
                                     const char *ip_or_domain,
                                     uint16_t port)
{
    CcnetPeer *peer;

    g_return_val_if_fail (ip_or_domain != NULL, NULL);
    g_return_val_if_fail (port != 0, NULL);

    peer = ccnet_peer_new (NON_RESOLVED_PEERID);
    peer->public_addr = g_strdup (ip_or_domain);
    peer->public_port = port;
    peer->to_resolve = 1;
    peer->manager = manager;
    
    manager->priv->resolve_peers = g_list_prepend (
        manager->priv->resolve_peers, peer);
    g_object_ref (peer);

    ccnet_conn_manager_add_to_conn_list (manager->session->connMgr,
                                         peer);
    ccnet_conn_manager_connect_peer (manager->session->connMgr,
                                     peer);
    return peer;
}


GList *
ccnet_peer_manager_get_resolve_peers (CcnetPeerManager *manager)
{
    GList *ret, *ptr;
    
    ret = g_list_copy(manager->priv->resolve_peers);
    for (ptr = ret; ptr; ptr = ptr->next) {
        g_object_ref ((CcnetPeer*)ptr->data);
    }
    return ret;
}

/*
  This function is intend to do valid check after peer's ID is resolved.

  This function is called when peer's ID is resolved, peer's public
  info is fetched, and connection is established. Return TRUE if
  start_keepalive() should be called after this function's
  return. Return FALSE otherwise.
 */
gboolean
ccnet_peer_manager_on_peer_resolved (CcnetPeerManager *manager,
                                     CcnetPeer *peer)
{
    peer->to_resolve = 0;
    ccnet_conn_manager_remove_from_conn_list (manager->session->connMgr, peer);

    save_peer_addr (manager, peer);
    CcnetPeer *old_peer;
    
    old_peer = ccnet_peer_manager_get_peer (manager, peer->id);
    if (old_peer) {
        if (old_peer->net_state == PEER_CONNECTED) {
            /* Actually this can't happen, because the otherside won't let you connect,
             * if you already has a connection to it. */
            /* use old peer instead */
            ccnet_warning ("[Peer Resolve] Resolved an already exists peer.\n");
            g_object_unref (old_peer);
            return FALSE;
        } else {
            ccnet_warning ("[Peer Resolve] Resolved an exists peer, replace it.\n");
            ccnet_peer_manager_remove_peer (manager, old_peer);
            g_object_unref (old_peer);
        }
    }

    manager->priv->resolve_peers = g_list_remove (
        manager->priv->resolve_peers, peer);
    g_object_unref (peer);

    ccnet_peer_manager_add_peer (manager, peer);

    if (peer->intend_role) {
        ccnet_peer_manager_add_role (manager, peer, peer->intend_role);
        g_free (peer->intend_role);
    }

    if (peer->want_tobe_relay) {
        ccnet_peer_manager_add_role (manager, peer, "MyRelay");
    }
    return TRUE;
}

void
ccnet_peer_manager_on_peer_resolve_failed (CcnetPeerManager *manager,
                                           CcnetPeer *peer)
{
    ccnet_peer_shutdown (peer);
    ccnet_conn_manager_remove_from_conn_list (manager->session->connMgr, peer);
    manager->priv->resolve_peers = g_list_remove (
        manager->priv->resolve_peers, peer);
    g_object_unref (peer);
}


/* -------- Peer Database Management ---------------- */

static void check_db_table (CcnetDB *db)
{
    char *sql;

    sql = "CREATE TABLE IF NOT EXISTS PeerAddr (peer_id CHAR(41) "
        "PRIMARY KEY, addr VARCHAR(15), port INTEGER)";
    ccnet_db_query (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS PeerRole (peer_id CHAR(41) PRIMARY KEY,"
        "roles TEXT, timestamp BIGINT)";
    ccnet_db_query (db, sql);
}


static CcnetDB *
open_sqlite_db (CcnetPeerManager *manager)
{
    CcnetDB *db = NULL;
    char *db_dir;
    char *db_path;

    db_dir = g_build_filename (manager->session->config_dir, "PeerMgr", NULL);
    if (checkdir_with_mkdir(db_dir) < 0) {
        ccnet_error ("Cannot open db dir %s: %s\n", db_dir,
                     strerror(errno));
        g_free (db_dir);
        return NULL;
    }
    g_free (db_dir);

    db_path = g_build_filename (manager->session->config_dir, "PeerMgr",
                                "peermgr.db", NULL);
#ifdef CCNET_SERVER
    db = ccnet_db_new_sqlite (db_path);
#else
    if (sqlite_open_db (db_path, &db) < 0)
        db = NULL;
#endif
    g_free (db_path);

    return db;
}

static int
open_db (CcnetPeerManager *manager)
{
    CcnetDB *db;

    db = open_sqlite_db (manager);
    if (!db)
        return -1;
    manager->priv->db = db;
    check_db_table (db);
    return 0;
}

static gboolean load_peer_addr_cb (CcnetDBRow *row, void *data)
{
    CcnetPeer *peer = (CcnetPeer *)data;
    char *addr = (char *) ccnet_db_row_get_column_text (row, 0);
    int port = ccnet_db_row_get_column_int (row, 1);

    peer->public_addr = g_strdup(addr);
    peer->public_port = port;
    return FALSE;
}

static void
load_peer_addr(CcnetPeerManager *manager, CcnetPeer *peer)
{
    char sql[256];

    if (!peer || !peer->id)
        return;

    snprintf (sql, 256, "SELECT addr, port FROM PeerAddr WHERE peer_id='%s'",
              peer->id);
    ccnet_db_foreach_selected_row (manager->priv->db, sql,
                                   load_peer_addr_cb, peer);
}

static void
save_peer_addr(CcnetPeerManager *manager, CcnetPeer *peer)
{
    /*
    char sql[256];

    if (!peer || !peer->id)
        return;

    if (peer->public_addr) {
        snprintf (sql, 256, "REPLACE INTO PeerAddr VALUES ('%s', '%s', '%d')",
                  peer->id, peer->public_addr, peer->public_port);
    } else {
        snprintf (sql, 256, "DELETE FROM PeerAddr WHERE peer_id='%s'",
                  peer->id);
    }
    ccnet_db_query (manager->priv->db, sql);
    */
}

static gboolean load_peer_role_cb (CcnetDBRow *row, void *data)
{
    CcnetPeer *peer = (CcnetPeer *)data;
    char *roles = (char *) ccnet_db_row_get_column_text (row, 0);

    ccnet_peer_set_roles (peer, roles);
    return FALSE;
}

static void load_peer_role(CcnetPeerManager *manager, CcnetPeer *peer)
{
    char sql[256];

    if (!peer) return;

    snprintf (sql, 256, "SELECT roles FROM PeerRole"
              " where peer_id = '%s'", peer->id);
    ccnet_db_foreach_selected_row (manager->priv->db, sql,
                                   load_peer_role_cb, peer);
}

static CcnetPeer*
_load_peer (CcnetPeerManager *manager, const char *path)
{
    GError *error = NULL;
    CcnetPeer *peer;
    char *content;

    g_file_get_contents (path, &content, NULL, &error);
    if (error != NULL) {
        /* ccnet_debug ("Load peer info from %s error: %s\n", */
        /*              path, error->message); */
        return NULL;
    }

    peer = ccnet_peer_from_string (content);
    if (!peer) {
        ccnet_warning ("Load peer info from %s error\n", path);
        g_free (content);
        return NULL;
    }

    load_peer_addr (manager, peer);
    load_peer_role (manager, peer);
    add_peer (manager, peer);
    peer->last_down = time(NULL);
    g_free (content);
    return peer;
}

void
ccnet_peer_manager_set_peer_public_addr (CcnetPeerManager *manager,
                                         CcnetPeer *peer,
                                         const char *addr,
                                         int port)
{
    int need_save = 0;
    if (port == 0)
        port = DEFAULT_PORT;
    if (!addr) {
        if (peer->public_addr) {
            g_free (peer->public_addr);
            peer->public_addr = NULL;
            need_save = 1;
        }
    } else if (!peer->public_addr || g_strcmp0 (peer->public_addr, addr) != 0){
        g_free (peer->public_addr);
        peer->public_addr = g_strdup (addr);
        need_save = 1;
    }
    if (port > 0 && port != peer->public_port) {
        peer->public_port = port;
        need_save = 1;
    }
    if (need_save)
        save_peer_addr (manager, peer);
}


static void
remove_peer_roles(CcnetPeerManager *manager, char *peer_id)
{
    /*
    char sql[256];

    if (!peer_id)
        return;

    snprintf (sql, 256, "DELETE FROM PeerRole WHERE peer_id = '%s'", peer_id);
    ccnet_db_query (manager->priv->db, sql);
    */
}


static void
save_peer_roles (CcnetPeerManager *manager, CcnetPeer *peer)
{
    /*
    char sql[512];
    CcnetDB *db = manager->priv->db;

    GString *buf = g_string_new (NULL);

    ccnet_peer_get_roles_str(peer, buf);
    snprintf (sql, 512, "REPLACE INTO PeerRole VALUES ('%s', '%s', "
              "%"G_GINT64_FORMAT")",
              peer->id, buf->str, get_current_time());
    ccnet_db_query (db, sql);
    g_string_free (buf, TRUE);
    */
}

void
ccnet_peer_manager_add_role (CcnetPeerManager *manager,
                             CcnetPeer *peer,
                             const char *role)
{
    ccnet_peer_add_role (peer, role);
    save_peer_roles (manager, peer);
}

void ccnet_peer_manager_remove_role (CcnetPeerManager *manager,
                                     CcnetPeer *peer,
                                     const char *role)
{
    ccnet_peer_remove_role (peer, role);
    save_peer_roles (manager, peer);
}

CcnetPeer*
ccnet_peer_manager_load_peer_by_id (CcnetPeerManager *manager,
                                    const char *peer_id)
{
    char path[PATH_MAX];

    g_return_val_if_fail (strlen(peer_id) == 40, NULL);

    sprintf (path, "%s" G_DIR_SEPARATOR_S "%s", manager->peerdb_path, peer_id);

    return _load_peer (manager, path);
}

static void prune_peers (CcnetPeerManager *manager)
{
    GList *peers, *ptr;

    peers = g_hash_table_get_values (manager->peer_hash);
    for (ptr = peers; ptr; ptr = ptr->next) {
        CcnetPeer *peer = ptr->data;
        if (peer->is_self)
            continue;
        if (peer->role_list == NULL) {
            ccnet_debug ("Removed peer %s\n", peer->id);
            delete_peer (manager, peer);
        }
    }

    g_list_free (peers);
}

void
ccnet_peer_manager_load_peerdb (CcnetPeerManager *manager)
{
    const char *dname;
    GDir *dp;
    char buf[PATH_MAX];

    manager->peerdb_path = g_build_filename (manager->session->config_dir,
                                             PEERDB_NAME, NULL);
    char *peerdb = manager->peerdb_path;

    open_db(manager);

    if (checkdir_with_mkdir(peerdb) < 0) {
        ccnet_warning ("Could not open or make peer-db.\n");
        return;
    }
        
    if ((dp = g_dir_open (peerdb, 0, NULL)) == NULL) {
        ccnet_warning ("Can't open peer database %s: %s.\n", peerdb,
                       strerror (errno));
        return;
    }

    while ((dname = g_dir_read_name(dp)) != NULL) {
        if (strlen(dname) != 40)
            continue;

        sprintf (buf, "%s/%s", peerdb, dname);
        if (!g_file_test(buf, G_FILE_TEST_IS_REGULAR)) {
            ccnet_warning ("%s is not a regular file\n", buf);
            continue;
        }

        CcnetPeer *peer = _load_peer (manager, buf);
        g_object_unref (peer);
    }
    g_dir_close(dp);

    prune_peers (manager);
}

CcnetPeer *
ccnet_peer_manager_get_peer (CcnetPeerManager *manager,
                             const char    *peer_id)
{
    CcnetPeer *peer;

    peer = g_hash_table_lookup (manager->peer_hash, peer_id);
    if (peer)
        g_object_ref (peer);
    return peer;
}

CcnetPeer*
ccnet_peer_manager_get_peer_by_name (CcnetPeerManager *manager,
                                     const char *name)
{
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, manager->peer_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        CcnetPeer *peer = value;
        if (peer->name == NULL)
            continue;
        if (strcmp(name, peer->name) == 0) {
            g_object_ref (peer);
            return peer;
        }
    }

    return NULL;
}

void
ccnet_peer_manager_add_local_peer (CcnetPeerManager *manager, CcnetPeer *peer)
{
    g_return_if_fail (peer->is_local);

    peer->manager = manager;
    manager->local_peers = g_list_append (manager->local_peers, peer);
    g_object_ref (peer);
}

void
ccnet_peer_manager_remove_local_peer (CcnetPeerManager *manager,
                                      CcnetPeer *peer)
{
    g_return_if_fail (peer->is_local);

    manager->local_peers = g_list_remove (manager->local_peers, peer);
    g_object_unref (peer);
}


static void save_peer (CcnetPeerManager *manager, CcnetPeer *peer)
{
    /*
    char *path = NULL;
    FILE *fp;

    path = g_build_filename (manager->peerdb_path, peer->id, NULL);

    GString *str = ccnet_peer_to_string (peer);

    if ((fp = g_fopen (path, "wb")) == NULL) {
        ccnet_warning ("Can't save peer info: %s\n", strerror(errno));
        goto err;
    }

    fputs (str->str, fp);
    fclose (fp);

err:
    g_string_free (str, TRUE);
    g_free (path);
    */
}

static int save_pulse (void * vmanager)
{
    CcnetPeerManager *manager = vmanager;
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, manager->peer_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        CcnetPeer *peer = value;

#ifdef CCNET_SERVER
        /* clean peers in memory */
        if (peer->role_list == NULL) {
            if (peer->net_state == PEER_DOWN && !peer->in_shutdown
                && !peer->in_connection) {
                time_t now = time(NULL);
                if (now < peer->last_down + PEER_GC_TIMEOUT)
                    continue;
                g_hash_table_iter_remove (&iter);
                g_object_unref (peer);
            }
        }
#endif

        if (peer->role_list == NULL)
            continue;
        
        if (peer->need_saving) {
            ccnet_debug ("[Peer] Saving peer %s(%.8s) to db\n",
                         peer->name, peer->id);
            save_peer (manager, peer);
            peer->need_saving = 0;
        }

    }
    
    return TRUE;
}

void
ccnet_peer_manager_start (CcnetPeerManager *manager)
{
    ccnet_timer_new (save_pulse, manager, SAVING_INTERVAL_MSEC);

    /* manager->priv->notify_timer = ccnet_timer_new ((TimerCB)notify_pulse, */
    /*                                                manager, NOTIFY_MSEC); */
}


static void
shutdown_peer (gpointer key, gpointer value, gpointer user_data)
{
    CcnetPeer *peer = value;

    if (!peer->is_self)
        ccnet_peer_shutdown (peer);
}


void ccnet_peer_manager_on_exit (CcnetPeerManager *manager)
{
    save_pulse (manager);
    g_hash_table_foreach (manager->peer_hash, shutdown_peer, manager);
}




/* -------- peermgr message handling -------- */

#ifdef CCNET_SERVER

#include "server-session.h"
#include "user-mgr.h"


#endif  /* CCNET_SERVER */


void
ccnet_peer_manager_send_ready_message (CcnetPeerManager *manager, CcnetPeer *peer)
{
    CcnetMessage *ready_message = NULL;
    char buf[256];

    snprintf (buf, 256, "v%d\n%s\n", PEERMGR_VERSION, SERVICE_READY);
    ready_message = ccnet_message_new (manager->session->base.id,
                                       peer->id, IPEERMGR_APP,
                                       buf, 0);
    ccnet_send_message (manager->session, ready_message);
    ccnet_message_unref (ready_message);
}

static void
handle_service_ready_message (CcnetPeerManager *manager,
                              CcnetMessage *msg,
                              char *body)
{
    CcnetPeer *peer = ccnet_peer_manager_get_peer (manager, msg->from);
    peer->is_ready = 1;
    ccnet_debug ("[peer] Received ready from peer %s(%.8s)\n", peer->name, peer->id);

    g_object_unref (peer);
}

static void
notify_peer_role (CcnetPeerManager *manager, CcnetPeer *peer)
{
    ccnet_debug ("[PeerMgr] Notify roles to peer %s(%.8s)\n", peer->name,
                 peer->id);

    GString *msgbuf = g_string_new(NULL);
    g_string_append_printf (msgbuf, "v%d\n%s\n", PEERMGR_VERSION,
                            ROLE_NOTIFY);
    ccnet_peer_get_roles_str (peer, msgbuf);
    g_string_append (msgbuf, "\n");

    CcnetMessage *msg = ccnet_message_new (manager->session->base.id,
                                           peer->id, IPEERMGR_APP,
                                           msgbuf->str, 0);
    ccnet_send_message (manager->session, msg);
    ccnet_message_unref (msg);

    g_string_free (msgbuf, TRUE);
}

void
ccnet_peer_manager_notify_peer_role (CcnetPeerManager *manager, CcnetPeer *peer)
{
    /* notify_peer_role (manager, peer); */
}

static void
handle_role_notify_message (CcnetPeerManager *manager,
                            CcnetMessage *msg,
                            char *body)
{
    ccnet_debug ("[PeerMgr] Receive role notify message\n");
    char *roles, *ptr;

    roles = body;
    if ( (ptr = strchr (body, '\n')) == NULL) {
        ccnet_message ("[PeerMgr] Parse role notify message error\n");
        return;
    }
    *ptr = '\0';
    
    CcnetPeer *peer = ccnet_peer_manager_get_peer (manager, msg->from);
    if (!peer) {
        return;
    }

    GList *role_list = string_list_parse_sorted (roles, ",");
    if (!string_list_sorted_is_equal (role_list, peer->myrole_list)) {
        ccnet_peer_set_myroles (peer, roles);
    }
    string_list_free (role_list);
    g_object_unref (peer);
}

static int
redirect (CcnetPeer *peer)
{
    ccnet_peer_shutdown (peer);
    ccnet_debug("[PeerMgr] connect redirect destination %s(%.8s): %s:%d\n",
                peer->name, peer->id, peer->redirect_addr, peer->redirect_port);
    ccnet_conn_manager_connect_peer (peer->manager->session->connMgr, peer);
    g_object_unref (peer);
    return FALSE;
}

static void
schedule_redirect (CcnetPeerManager *manager, CcnetPeer *peer)
{
    g_object_ref (peer);
    ccnet_timer_new ((TimerCB)redirect, peer, 1);
}

static void
handle_redirect_message (CcnetPeerManager *manager,
                         CcnetMessage *msg,
                         char *body)
{
    int port;
    char *p, *addr;
    CcnetPeer *from;
    int len;

    ccnet_debug ("[PeerMgr] Receive redirect message from %.8s\n",
                 msg->from);

    len = strlen(body);
    if (body[len-1] != '\n') {
        ccnet_message ("[PeerMgr] Bad formatted redirect msg: not end with '\\n'\n");
        return;
    }
    body[len-1] = '\0';

    addr = body;
    if ( (p = strchr(body, ':')) == NULL) {
        ccnet_message ("[PeerMgr] Bad formatted redirect msg: port missing\n");
        return;
    }
    *p = '\0';
    port = atoi(p+1);
    if (port <= 0) {
        ccnet_message ("[PeerMgr] Bad formatted redirect msg: wrong port\n");
        return;
    }


    from = ccnet_peer_manager_get_peer (manager, msg->from);
    ccnet_peer_set_redirect (from, addr, port);
    /* note: can shutdown the connection during this event iteration,
     * must schedule it */
    schedule_redirect (manager, from);

    g_object_unref (from);
}

void
ccnet_peer_manager_receive_message (CcnetPeerManager *manager,
                                    CcnetMessage *msg)
{
    guint16 version;
    char *type;
    char *body;

    if (parse_peermgr_message (msg, &version, &type, &body) < 0) {
        ccnet_message ("Invalid peermgr message from %.8s\n", msg->from);
        return;
    }

    if (version != PEERMGR_VERSION) {
        ccnet_message ("Incompatible peermgr message version %d from %.8s\n",
                       version, msg->from);
        return;
    }

    if (strcmp(type, ROLE_NOTIFY) == 0)
        handle_role_notify_message (manager, msg, body);
    else if (strcmp(type, SERVICE_READY) == 0)
        handle_service_ready_message (manager, msg, body);
    else if (strcmp(type, PEER_REDIRECT) == 0)
        handle_redirect_message (manager, msg, body);
}


static void
send_redirect_message (CcnetPeerManager *manager, CcnetPeer *peer,
                       CcnetPeer *to)
{
    CcnetMessage *msg = NULL;
    char buf[256];

    if (!to->public_addr || to->public_port == 0) {
        ccnet_warning ("[peer] Redirect to peer %s(%.8s) has an invalid address\n",
                       to->name, to->id);
        return;
    }
    snprintf (buf, 256, "v%d\n%s\n%s:%d\n", PEERMGR_VERSION, PEER_REDIRECT,
              to->public_addr, to->public_port);

    msg = ccnet_message_new (manager->session->base.id,
                             peer->id, IPEERMGR_APP,
                             buf, 0);
    ccnet_send_message (manager->session, msg);
    ccnet_message_unref (msg);
}

void
ccnet_peer_manager_redirect_peer (CcnetPeerManager *manager,
                                  CcnetPeer *peer,
                                  CcnetPeer *to)
{
    ccnet_debug ("[PeerMgr] redirect peer %s(%.8s) to %s(%.8s)\n",
                 peer->name, peer->id,
                 to->name, to->id);
    send_redirect_message (manager, peer, to);

    return;
}

void
ccnet_peer_manager_on_peer_session_key_sent (CcnetPeerManager *manager,
                                             CcnetPeer *peer)
{
    g_signal_emit_by_name (manager, "peer-auth-done", peer);
}

void
ccnet_peer_manager_on_peer_session_key_received (CcnetPeerManager *manager,
                                                 CcnetPeer *peer)
{
    g_signal_emit_by_name (manager, "peer-auth-done", peer);
}

