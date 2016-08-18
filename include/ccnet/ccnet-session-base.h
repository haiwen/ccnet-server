/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_SESSION_BASE_H
#define CCNET_SESSION_BASE_H

#include <glib-object.h>

#define CCNET_TYPE_SESSION_BASE                  (ccnet_session_base_get_type ())
#define CCNET_SESSION_BASE(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_SESSION_BASE, CcnetSessionBase))
#define CCNET_IS_SESSION_BASE(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_SESSION_BASE))
#define CCNET_SESSION_BASE_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_SESSION_BASE, CcnetSessionBaseClass))
#define CCNET_IS_SESSION_BASE_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_SESSION_BASE))
#define CCNET_SESSION_BASE_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_SESSION_BASE, CcnetSessionBaseClass))

#define CCNET_PIPE_NAME "ccnet.sock"

typedef struct _CcnetSessionBase CcnetSessionBase;
typedef struct _CcnetSessionBaseClass CcnetSessionBaseClass;

struct _CcnetSessionBase {
    GObject         parent_instance;

    char            id[41];
    unsigned char   id_sha1[20];

    char           *user_name;

    char           *name;

    int             public_port;
    int             net_status;

    char           *service_url;
    char           *relay_id;
};


struct _CcnetSessionBaseClass {
    GObjectClass    parent_class;
};


GType ccnet_session_base_get_type (void);

CcnetSessionBase *ccnet_session_base_new (void);

#endif
