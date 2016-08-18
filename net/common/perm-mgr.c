/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "peer.h"
#include "session.h"
#include "peer-mgr.h"
#include "perm-mgr.h"

#define DEBUG_FLAG CCNET_DEBUG_OTHER
#include "log.h"

/* Give an user and a service, for each role of this user:
      1. find the service group,
      2. use hash table 'role2groups' to find the permitted groups to this role,
      3. check whether the given group in the list of groups.
*/

struct _CcnetPermManagerPriv {
    GHashTable   *serv2group;       /* service to group map */
    GHashTable   *role2groups;      /* role -> list of groups */
    GList        *anonymous_groups; /* permitted groups to anonymous user. */
};

struct ServiceGroup {
    const char *service;
    const char *group;
};

/* only service that can be accessed from network peers should list here,
 * service accessed only by local peers do not need be list here. */
struct ServiceGroup service_groups[] = {
    { "put-pubinfo",                    "basic" },
    { "put-user",                       "basic" },
    { "keepalive2",                     "basic" },
    { "receive-session-key",            "basic" },
    { "receive-skey2",                  "basic" },
    { "receive-msg",                    "basic" },
    { "echo",                           "basic" },
    { "ccnet-rpcserver",                "rpc-inner" },
#ifdef CCNET_SERVER
    { "recvlogin",                      "basic" },
    { "recvlogout",                     "basic" },
    { "receive-profile",                "relay-service" },
#endif
    { NULL, NULL },
};

struct RolePerm {
    const char *role;
    const char *group;
};

typedef struct RolePermList {
    GList *list;
} RolePermList;

struct RolePerm role_perms[] = {
    { "MyClient", "seafserv" },
    { "MyClient", "relay-service" },
    { "MyAdmin", "rpc-inner" },
    { "ClusterMember", "seafserv-inner" },
    { "BlockClient", "seablock" },
    { NULL, NULL },
};

CcnetPermManager *
ccnet_perm_manager_new (CcnetSession *session)
{
    CcnetPermManager *mgr = g_new0 (CcnetPermManager, 1);
    mgr->priv = g_new0 (CcnetPermManagerPriv, 1);
    mgr->session = session;
    mgr->priv->serv2group = g_hash_table_new (g_str_hash, g_str_equal);
    mgr->priv->role2groups = g_hash_table_new (g_str_hash, g_str_equal);
    return mgr;
}

static void populate_default_items(CcnetPermManager *mgr);

int
ccnet_perm_manager_prepare (CcnetPermManager *mgr)
{
    populate_default_items (mgr);
    return 0;
}

static void
populate_default_items (CcnetPermManager *mgr)
{
    struct ServiceGroup *sg;
    for (sg = service_groups; sg->service; sg++) {
        g_hash_table_insert (mgr->priv->serv2group, g_strdup(sg->service),
                             g_strdup(sg->group));
    }

    struct RolePerm *rp;
    for (rp = role_perms; rp->role; rp++) {
        RolePermList *list;
        list = g_hash_table_lookup (mgr->priv->role2groups, rp->role);
        if (!list) {
            list = g_new0(RolePermList, 1);
            g_hash_table_insert (mgr->priv->role2groups, g_strdup(rp->role),
                                 list);
        }
        list->list = g_list_prepend (list->list, g_strdup(rp->group));
    }
}

static inline const char *
get_service_group(CcnetPermManager *mgr, const char *service)
{
    return g_hash_table_lookup (mgr->priv->serv2group, service);
}

int
check_role_permission(CcnetPermManager *mgr, const char *role, const char *group)
{
    RolePermList *rplist;
    GList *ptr;

    rplist = g_hash_table_lookup (mgr->priv->role2groups, role);
    if (!rplist)
        return PERM_CHECK_ERROR;

    for (ptr = rplist->list; ptr; ptr = ptr->next) {
        if (strcmp(ptr->data, group) == 0)
            return PERM_CHECK_OK;
    }
    return PERM_CHECK_ERROR;
}

/* for unit test */
int
ccnet_perm_manager_check_role_permission(CcnetPermManager *mgr,
                                         const char *role, const char *group)
{
    return check_role_permission (mgr, role, group);
}

int
ccnet_perm_manager_check_permission (CcnetPermManager *mgr,
                                     CcnetPeer *peer,
                                     const char *req,
                                     int req_id,
                                     int argc, char **argv)
{
    const char *group = get_service_group (mgr, req);
    if (!group)
        return PERM_CHECK_NOSERVICE;

    if (g_strcmp0(group, "basic") == 0)
        return PERM_CHECK_OK;

    if (peer->is_local)
        return PERM_CHECK_OK;

    if (g_strcmp0(group, "inner") == 0)
        return PERM_CHECK_ERROR;

    if (g_strcmp0 (group, "self") == 0) {
        if (g_strcmp0 (peer->id, mgr->session->base.id) == 0)
            /* myself user */
            return PERM_CHECK_OK;
        else
            return PERM_CHECK_ERROR;
    }

    GList *ptr;
    for (ptr = peer->role_list; ptr; ptr = ptr->next) {
        if (check_role_permission(mgr, ptr->data, group) == PERM_CHECK_OK)
            return PERM_CHECK_OK;
    }

    return PERM_CHECK_ERROR;
}

int
ccnet_perm_manager_register_service (CcnetPermManager *mgr,
                                     const char *service,
                                     const char *group,
                                     CcnetPeer *peer)
{
    if (g_hash_table_lookup (mgr->priv->serv2group, service))
        return -1;

    ccnet_debug ("[perm-mgr] register service %s %s\n", service, group);
    g_hash_table_insert (mgr->priv->serv2group, g_strdup(service),
                         g_strdup(group));
    return 0;
}
