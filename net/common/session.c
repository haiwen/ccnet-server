/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

#include "getgateway.h"
#include "utils.h"
#include "net.h"
#include "rsa.h"
#include "ccnet-config.h"

#include "session.h"
#include "peer.h"
#include "peer-mgr.h"
#include "perm-mgr.h"
#include "packet-io.h"
#include "connect-mgr.h"
#include "message.h"
#include "message-manager.h"
#include "algorithms.h"
#include "proc-factory.h"

#define DEBUG_FLAG CCNET_DEBUG_OTHER
#include "log.h"

#define THREAD_POOL_SIZE 50
#define DEFAULT_NAME "server"
#define DEFAULT_ID "8e4b13b49ca79f35732d9f44a0804940d985627c"
static char PRIVATE_KEY[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpAIBAAKCAQEAuZFwgxkKQGaqYyFMxIUz1JHnZPaOgEQ+fX/jRVYbGMiHkSbX\n"
"K9X3XUHUGEjUt8b3zW6UZJGjgyV5S08YuaN0eE5z6Q6bnuWEhkTmgZgXaybc9Hiu\n"
"y2WAHpKj+qbXcmewE0WEys/Ov9AIe0TRXmvL6r1793VcLSzgb/aIQA2WFg97DfEA\n"
"hGAHo5BesKRfEEvXL6ZB9cGxXP9qIy0ObTvLXlOgbYchfV4rrXJk0u9xWjRyXABv\n"
"2Myv3fgxmGmTR+TAw2G5GCKeh9IoIuWVMGPyjSlERGMqQYymNz3NgyWFayyZ5HQS\n"
"tihCnflOGEiMHRkOwIczB16YZhan2YqKpsjHGwIBIwKCAQEArvbXzBBLfoyvR4XM\n"
"Cb9rYgXozOh3usQAZ7MYHM2HQ0C6VahHN/WgFhl+1RF4Gv1tTKoW4nqwHJEL9oxn\n"
"xPkzTNxBZrYAcT7NaKdc/diLG+LQVDdFuHWkrxyL+vUUR0vR5kjcSjGlrYmhmMvb\n"
"WQaNEIbFVwhA92TTnMPfjNmcI2wRKI1K9NEKDAMIPSwW/sgkls2h4KW3Y7DooJ0k\n"
"l0apjN/rlaR4ohZp6oMVifW8GFY43Xau+4dIrYTnvvSyvGvtB+8cWuhqqvWHRZdM\n"
"rFjgOJoZH5l0zxt2dYW2WFiqgT7xXsvu6L+nylXktEMxC33rehYdPrd427J409A6\n"
"caO5cwKBgQDyrBQ8UXu7cDAktiKTwH7+pA0wNyTvKsGYw0RcFILccpxty2r5gYhI\n"
"eLFPVyjoYxwauW6vX3cSAYLKR+2PlYvkPpEvBQIJbaurx++ejez/KxYD65ZeFTfs\n"
"Kb9A08hgMxCvJmnRvojhez1OZmmmWYPT57XeZXnCiNoyJWKA0mMNvwKBgQDDwn02\n"
"o5n7ugetXIlV1PiStVogPPTBobh9jsXooQFh4fB+lsrO082hapMlbVVNG1gLzvTY\n"
"V0oDM/AzdnC6feZlAEdM+IcruinVnMnbnhiwPVDInCJIhvmJ/XScvkTsgHwRiAss\n"
"Tlf8wH/uGXiaeVV/KMlkKRK6h54znTPq37/VpQKBgQDkziG1NuJgRTS05j3bxB/3\n"
"Z3omJV1Wh2YTsMtswuHIiVGpWWTcnrOyC2VZb2+2iVUDQR83oycfmwZJsYg27BYu\n"
"+SnNPzxvSiWEtTJiS00rGf7QfwoeMUNbAspEb+jPux5b/6WZ34hfkXRRO/02cagu\n"
"Mj3DDzhJtDtxG+8pAOEM9QKBgQC+KqWFiPv72UlJUpQKPJmzFpIQsD44cTbgXs7h\n"
"+32viwbhX0irqS4nxp2SEnAfBJ6sYqS05xSyp3uftOKJRxpTfJ0I8W1drYe5kP6a\n"
"1Bf7qUcpRzc/JAhaKWn3Wb9MJQrPM7MVGOfCVJmINgAhCCcrEa2xwX/oZnxsp1cB\n"
"a6RpIwKBgQDW15IebNwVOExTqtfh6UvIjMSrk9OoHDyjoPLI3eyPt3ujKdXFJ8qF\n"
"CWg9ianQyE5Y8vfDI+x1YRCOwq2WapeXzkSO8CzVFHgz5kFqJQolr4+o6wr5mLLC\n"
"+6iW9u81/X3bMAWshtNfsWbRSFLT1WNVTKRg+xO7YG/3wcyeIeqigA==\n"
"-----END RSA PRIVATE KEY-----\n";

static void ccnet_service_free (CcnetService *service);


G_DEFINE_TYPE (CcnetSession, ccnet_session, CCNET_TYPE_SESSION_BASE);

static void on_peer_auth_done (CcnetPeerManager *manager,
                               CcnetPeer *peer, gpointer user_data);

static void
ccnet_session_class_init (CcnetSessionClass *klass)
{
    /* GObjectClass *gobject_class = G_OBJECT_CLASS (klass); */
}

static void
ccnet_session_init (CcnetSession *session)
{
    /* note, the order is important. */
    session->service_hash = g_hash_table_new_full (
        g_str_hash, g_str_equal, 
        g_free, (GDestroyNotify)ccnet_service_free);
    session->proc_factory = ccnet_proc_factory_new (session);
    session->peer_mgr = ccnet_peer_manager_new (session);
    session->connMgr = ccnet_conn_manager_new (session);
    session->msg_mgr = ccnet_message_manager_new (session);
    session->perm_mgr = ccnet_perm_manager_new (session);
    session->job_mgr = ccnet_job_manager_new (THREAD_POOL_SIZE);
}

static int load_rsakey(CcnetSession *session)
{
    RSA *key = NULL;
    BIO *bufio = NULL;

    bufio = BIO_new_mem_buf((void*)PRIVATE_KEY, -1);
    PEM_read_bio_RSAPrivateKey(bufio, &key, NULL, NULL);
    BIO_free (bufio);

    session->privkey = key;
    session->pubkey = private_key_to_pub(key);

    return 0;
}

static void save_pubinfo (CcnetSession *session);

CcnetSession *
ccnet_session_new ()
{
    return g_object_new (CCNET_TYPE_SESSION, NULL);
}

int
ccnet_session_load_config (CcnetSession *session,
                           const char *central_config_dir_r,
                           const char *config_dir_r)
{
    int ret = 0;
    char *config_file = NULL, *config_dir = NULL, *central_config_dir = NULL;
#ifdef CCNET_SERVER
    char *service_url;
#endif
    unsigned char sha1[20];
    GKeyFile *key_file;

    config_dir = ccnet_expand_path (config_dir_r);

    if (checkdir(config_dir) < 0) {
        ccnet_error ("Config dir %s does not exist or is not "
                     "a directory.\n", config_dir);
        return -1;
    }

#ifdef CCNET_SERVER
    if (central_config_dir_r) {
        central_config_dir = ccnet_expand_path (central_config_dir_r);
        if (checkdir(central_config_dir) < 0) {
            ccnet_error ("Server Config dir %s does not exist or is not "
                         "a directory.\n", central_config_dir);
            return -1;
        }
    }
#endif

    config_file = g_build_filename (central_config_dir ? central_config_dir : config_dir,
                                    SESSION_CONFIG_FILENAME, NULL);
    ccnet_message ("using config file %s\n", config_file);
    key_file = g_key_file_new ();
    g_key_file_set_list_separator (key_file, ',');
    if (!g_key_file_load_from_file (key_file, config_file,
                                    G_KEY_FILE_KEEP_COMMENTS, NULL))
    {
        ccnet_warning ("Can't load config file %s.\n", config_file);
        return -1;
    }

#ifdef CCNET_SERVER
    service_url = ccnet_key_file_get_string (key_file, "General", "SERVICE_URL");
#endif

    memcpy (session->base.id, DEFAULT_ID, 40);
    session->base.id[40] = '\0';
    if (hex_to_sha1 (session->base.id, sha1) < 0) {
         ccnet_error ("Failed to get sha1 of ID.\n");
         ret = -1;
         goto onerror;
    }
    session->base.name = DEFAULT_NAME;
    session->base.public_port = DEFAULT_PORT;
#ifdef CCNET_SERVER
    session->base.service_url = g_strdup(service_url);
#endif
    session->config_file = config_file;
    session->config_dir = config_dir;
    session->central_config_dir = central_config_dir;
    session->keyf = key_file;

    load_rsakey(session);

    ret = 0;

onerror:
#ifdef CCNET_SERVER
    g_free (service_url);
#endif
    return ret;
}

void
ccnet_session_free (CcnetSession *session)
{
    ccnet_peer_manager_free (session->peer_mgr);

    g_object_unref (session);
}


int
ccnet_session_prepare (CcnetSession *session,
                       const char *central_config_dir,
                       const char *config_dir_r,
                       gboolean test_config)
{
    char *misc_path;
    int ret;

    if (ccnet_session_load_config (session, central_config_dir, config_dir_r) < 0)
        return -1;

    misc_path = g_build_filename (session->config_dir, "misc", NULL);
    if (checkdir_with_mkdir (misc_path) < 0) {
        ccnet_error ("mkdir %s error", misc_path);
        return -1;
    }

    /* config db */
    session->config_db = ccnet_session_config_open_db (misc_path);
    if (!session->config_db) {
        ccnet_warning ("Failed to open config db.\n");
        return -1;
    }
    
    /* call subclass prepare */
    ret = CCNET_SESSION_GET_CLASS (session)->prepare(session);
    if (ret < 0)
        return ret;

    /* peer */
    ccnet_peer_manager_prepare(session->peer_mgr);
    g_signal_connect (session->peer_mgr, "peer-auth-done",
                      G_CALLBACK(on_peer_auth_done), session);

    /* permission manager */
    ccnet_perm_manager_prepare (session->perm_mgr);

    g_free (misc_path);

    if (test_config) {
        return 0;
    } else {
        /* refresh pubinfo on every startup */
        save_pubinfo (session);
    }

    return 0;
}


static void
save_peerinfo (CcnetSession *session)
{
    FILE *fp;
    char *path;
    char filename[64];
    
    sprintf(filename, "%s%s", session->base.id, ".peer");
    path = g_build_filename (session->config_dir, "misc", filename, NULL);

    if ((fp = g_fopen(path, "wb")) == NULL) {
        ccnet_warning ("Open public info file %s error: %s\n",
                       path, strerror(errno));
        g_free (path);
        return;
    }
    g_free (path);

    ccnet_message ("Update pubinfo file\n");
    session->myself->public_port = session->base.public_port;

    GString *str = ccnet_peer_to_string (session->myself);
    fputs (str->str, fp);
    fclose (fp);
    g_string_free (str, TRUE);
}


static void save_pubinfo (CcnetSession *session)
{
    save_peerinfo(session);
}

void
ccnet_session_save_config (CcnetSession *session)
{
    GError *error = NULL;
    char *str;
    FILE *fp;

    ccnet_message ("[Session] Saving configure file\n");
    if (session->saving_pub) {
        /* only update timestamp when pubinfo changes */
        save_pubinfo (session);
        session->saving_pub = 0;
    }

#ifdef CCNET_SERVER
    g_key_file_set_string (session->keyf, "General", "SERVICE_URL",
                           session->base.service_url?session->base.service_url:"");
#endif

    str = g_key_file_to_data (session->keyf, NULL, &error);
    if (error) {
        ccnet_warning ("Can't save unauth peer info: %s\n",
                       error->message);
        return;
    }

    if ((fp = g_fopen (session->config_file, "wb")) == NULL) {
        ccnet_warning ("Can't save session conf: %s\n", strerror(errno));
        g_free (str);
        return;
    }

    fputs (str, fp);
    fclose (fp);

    g_free (str);
    return;
}

void
ccnet_session_save (CcnetSession *session)
{
    /* ccnet_req_manager_backup_requirements (session->reqMgr); */
}

void
ccnet_session_on_exit (CcnetSession *session)
{
    time_t t;

    ccnet_peer_manager_on_exit (session->peer_mgr);
    ccnet_session_save (session);

    t = time(NULL);
    ccnet_message ("Exit at %s\n", ctime(&t));
    ccnet_session_free (session);
}


static const char *net_status_string (int status)
{
    switch (status) {
    case NET_STATUS_DOWN:
        return "Down";
    case NET_STATUS_INNAT:
        return "In nat";
    case NET_STATUS_FULL:
        return "Full";
    default:
        return "Unknown";
    }
}

void
ccnet_session_start_network (CcnetSession *session)
{
    session->base.net_status = NET_STATUS_FULL;
    ccnet_conn_manager_start (session->connMgr);
    session->myself->addr_str = NULL;
}

void
ccnet_session_shutdown_network (CcnetSession *session)
{
    GList *peers, *ptr;
    
    peers = ccnet_peer_manager_get_peer_list(session->peer_mgr);
    for (ptr = peers; ptr; ptr = ptr->next)
        ccnet_peer_shutdown ((CcnetPeer *)ptr->data);
    g_list_free (peers);

    ccnet_conn_manager_stop (session->connMgr);
}

static int
restart_network (CcnetSession *session)
{
    ccnet_session_start_network (session);
    if (session->base.net_status != NET_STATUS_DOWN) {
        session->start_failure = 0;
        return FALSE;
    }
    
    if (++session->start_failure > 3) 
        return FALSE;

    return TRUE;
}

void
ccnet_session_start (CcnetSession *session)
{
    ccnet_proc_factory_start (session->proc_factory);
    ccnet_message_manager_start (session->msg_mgr);

    if (session->base.public_port == 0) {
        return;
    }

    ccnet_session_start_network (session);
    if (session->base.net_status == NET_STATUS_DOWN) {
        ccnet_timer_new ((TimerCB)restart_network, session, 10000);
    }

    ccnet_peer_manager_start (session->peer_mgr);
}


static void
ccnet_service_free (CcnetService *service)
{
    g_free (service->svc_name);
    g_free (service);
}

int
ccnet_session_register_service (CcnetSession *session,
                                const char *svc_name,
                                const char *group,
                                CcnetPeer *peer)
{
    CcnetService *service = g_new0 (CcnetService, 1);

    if (g_hash_table_lookup (session->service_hash, svc_name)) {
        ccnet_debug ("[Service] Service %s has already been registered\n",
                     svc_name);
        return -1;
    }
    ccnet_debug ("[Service] Service %s registered\n", svc_name);

    ccnet_perm_manager_register_service (session->perm_mgr, svc_name,
                                         group, peer);

    service->svc_name = g_strdup(svc_name);
    service->provider = peer;

    g_hash_table_insert (session->service_hash, g_strdup(svc_name), service);

    return 0;
}

CcnetService*
ccnet_session_get_service (CcnetSession *session,
                           const char *svc_name)
{
    return g_hash_table_lookup (session->service_hash, svc_name);
}

gboolean remove_service_cmp (gpointer key,
                             gpointer value,
                             gpointer user_data)
{
    CcnetService *service = value;

    if (service->provider == user_data) {
        ccnet_debug ("[Service] Service %s un-registered\n", (char *)key);
        return TRUE;
    }
    return FALSE;
}

void
ccnet_session_unregister_service (CcnetSession *session,
                                  CcnetPeer *peer)
{
    g_hash_table_foreach_remove (session->service_hash, 
                                 remove_service_cmp, peer);
}


static void on_peer_auth_done (CcnetPeerManager *manager,
                               CcnetPeer *peer, gpointer user_data)
{
    CcnetSession *session = (CcnetSession *)user_data;
    
    CCNET_SESSION_GET_CLASS (session)->on_peer_auth_done(session, peer);
}


gboolean
ccnet_session_should_encrypt_channel (CcnetSession *session)
{
    return session->encrypt_channel;
}
