/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_PERM_MGR_H
#define SEAF_PERM_MGR_H

#include <glib.h>


enum {
    PERM_CHECK_ERROR = -1,
    PERM_CHECK_OK = 0,
    PERM_CHECK_DELAY = 1,
    PERM_CHECK_NOSERVICE = 2,
};

typedef struct _CcnetPermManager CcnetPermManager;
typedef struct _CcnetPermManagerPriv CcnetPermManagerPriv;

struct _CcnetPermManager {
    CcnetSession         *session;

    CcnetPermManagerPriv *priv;
};

CcnetPermManager*
ccnet_perm_manager_new (CcnetSession *session);

int
ccnet_perm_manager_prepare (CcnetPermManager *mgr);

int
ccnet_perm_manager_check_permission (CcnetPermManager *mgr,
                                     CcnetPeer *peer,
                                     const char *req,
                                     int req_id,
                                     int argc, char **argv);

int
ccnet_perm_manager_check_role_permission(CcnetPermManager *mgr,
                                         const char *role,
                                         const char *group);

int
ccnet_perm_manager_register_service (CcnetPermManager *mgr,
                                     const char *svc_name,
                                     const char *group,
                                     CcnetPeer *peer);
#endif
