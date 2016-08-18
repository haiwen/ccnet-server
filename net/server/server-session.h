/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_SERVER_SESSION_H
#define CCNET_SERVER_SESSION_H

#include <session.h>

#define CCNET_TYPE_SERVER_SESSION                  (ccnet_server_session_get_type ())
#define CCNET_SERVER_SESSION(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SERVER_SESSION, CcnetServerSession))
#define CCNET_IS_SERVER_SESSION(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SERVER_SESSION))
#define CCNET_SERVER_SESSION_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SERVER_SESSION, CcnetServerSessionClass))
#define CCNET_IS_SERVER_SESSION_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SERVER_SESSION))
#define CCNET_SERVER_SESSION_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SERVER_SESSION, CcnetServerSessionClass))

typedef struct CcnetServerSession CcnetServerSession;
typedef struct _CcnetServerSessionClass CcnetServerSessionClass;

struct CcnetServerSession
{
    CcnetSession                common_session;

    struct _CcnetUserManager   *user_mgr;
    struct _CcnetGroupManager  *group_mgr;
    struct _CcnetOrgManager    *org_mgr;
};

struct _CcnetServerSessionClass
{
    CcnetSessionClass  parent_class;
};

GType ccnet_server_session_get_type ();

CcnetServerSession *ccnet_server_session_new ();


#endif
