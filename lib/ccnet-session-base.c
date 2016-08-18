
#include "option.h"
#include "include.h"

#include "ccnet-session-base.h"

G_DEFINE_TYPE (CcnetSessionBase, ccnet_session_base, G_TYPE_OBJECT);

enum {
    P_ID = 1,
    P_USER_NAME,
    P_NAME,
    P_PUBLIC_PORT,
    P_NET_STATUS,
    P_DEFAULT_RELAY,
};


static void
set_property (GObject *object, guint property_id, 
              const GValue *v, GParamSpec *pspec)
{
    CcnetSessionBase *session = CCNET_SESSION_BASE (object);
    const char *relay;

    switch (property_id) {
    case P_ID:
        strcpy(session->id, g_value_get_string(v));
        break;
    case P_NAME:
        g_free (session->name);
        session->name = g_strdup (g_value_get_string(v));
        break;
    case P_USER_NAME:
        g_free (session->user_name);
        session->user_name = g_strdup (g_value_get_string(v));
        break;
    case P_PUBLIC_PORT:
        session->public_port = g_value_get_int (v);
        break;
    case P_NET_STATUS:
        session->net_status = g_value_get_int (v);
        break;
    case P_DEFAULT_RELAY:
        relay = g_value_get_string(v);
        session->relay_id = g_strdup(relay);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        return;
    }

}

static void
get_property (GObject *object, guint property_id,
              GValue *v, GParamSpec *pspec)
{
    CcnetSessionBase *session = CCNET_SESSION_BASE (object);

    switch (property_id) {
        /* commont properties to session and daemon */
    case P_ID:
        g_value_set_string (v, session->id);
        break;
    case P_USER_NAME:
        g_value_set_string (v, session->user_name);
        break;
    case P_NAME:
        g_value_set_string (v, session->name);
        break;
    case P_PUBLIC_PORT:
        g_value_set_int (v, session->public_port);
        break;
    case P_NET_STATUS:
        g_value_set_int (v, session->net_status);
        break;
    case P_DEFAULT_RELAY:
        g_value_set_string (v, session->relay_id);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
finalize(GObject *gobject)
{
    CcnetSessionBase *s = CCNET_SESSION_BASE(gobject);
    
    g_free (s->user_name);
    g_free (s->name);
    g_free (s->relay_id);

    G_OBJECT_CLASS(ccnet_session_base_parent_class)->finalize (gobject);
}


static void
ccnet_session_base_class_init (CcnetSessionBaseClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

    gobject_class->set_property = set_property;
    gobject_class->get_property = get_property;
    gobject_class->finalize = finalize;

    g_object_class_install_property (gobject_class, P_ID,
        g_param_spec_string ("id", NULL, "ID",
                             NULL, G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_USER_NAME,
        g_param_spec_string ("user-name", NULL, "User Name",
                             NULL, G_PARAM_READWRITE));

   g_object_class_install_property (gobject_class, P_NAME,
        g_param_spec_string ("name", NULL, "Name",
                             NULL, G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_PUBLIC_PORT,
        g_param_spec_int ("public-port", NULL, "Public Port",
                          0, 65525, 0, G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_NET_STATUS,
        g_param_spec_int ("net-status", NULL, "Network Status",
                          0, NET_STATUS_FULL, NET_STATUS_DOWN, 
                          G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_DEFAULT_RELAY,
        g_param_spec_string ("default-relay", NULL, "Default Relay", 
                             NULL, G_PARAM_READWRITE));
}

static void
ccnet_session_base_init (CcnetSessionBase *sbase)
{

}

CcnetSessionBase *
ccnet_session_base_new (void)
{
    return g_object_new (CCNET_TYPE_SESSION_BASE, NULL);
}
