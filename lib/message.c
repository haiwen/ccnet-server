/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "include.h"

#include "message.h"

enum {
    P_ID = 1,
    P_FLAGS,
    P_FROM,
    P_TO,
    P_CTIME,
    P_RTIME,
    P_APP,
    P_BODY,
};

G_DEFINE_TYPE (CcnetMessage, ccnet_message, G_TYPE_OBJECT);


static void
set_property (GObject *object, guint property_id, 
              const GValue *v, GParamSpec *pspec)
{
    /* CcnetMessage *message = CCNET_MESSAGE (object); */

    switch (property_id) {
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        return;
    }
}

static void
get_property (GObject *object, guint property_id,
              GValue *v, GParamSpec *pspec)
{
    CcnetMessage *message = CCNET_MESSAGE (object);

    switch (property_id) {
    case P_ID:
        g_value_set_string (v, message->id);
        break;
    case P_FLAGS:
        g_value_set_uint (v, message->flags);
        break;
    case P_FROM:
        g_value_set_string (v, message->from);
        break;
    case P_TO:
        g_value_set_string (v, message->to);
        break;
    case P_CTIME:
        g_value_set_uint (v, message->ctime);
        break;
    case P_RTIME:
        g_value_set_uint (v, message->rtime);
        break;
    case P_APP:
        g_value_set_string (v, message->app);
        break;
    case P_BODY:
        g_value_set_string (v, message->body);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void finalize (GObject *object)
{
    CcnetMessage *message = (CcnetMessage *)object;
    g_free (message->app);
    g_free (message->id);
    g_free (message->body);
}


static void
ccnet_message_class_init (CcnetMessageClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

    gobject_class->set_property = set_property;
    gobject_class->get_property = get_property;
    gobject_class->finalize = finalize;


    g_object_class_install_property (gobject_class, P_ID,
                    g_param_spec_string ("id", NULL, "ID", 
                             NULL, G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_FLAGS,
        g_param_spec_uint ("flags", NULL, "Flags",
                           0, UINT_MAX, 0, G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_FROM,
                    g_param_spec_string ("from_id", NULL, "From ID", 
                                         NULL, G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_TO,
                    g_param_spec_string ("to_id", NULL, "To ID", 
                                         NULL, G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_CTIME,
        g_param_spec_uint ("ctime", NULL, "Creation Time",
                           0, UINT_MAX, 0, G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_RTIME,
        g_param_spec_uint ("rtime", NULL, "Receiving Time",
                           0, UINT_MAX, 0, G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_APP,
                    g_param_spec_string ("app", NULL, "application", 
                                         NULL, G_PARAM_READWRITE));

    g_object_class_install_property (gobject_class, P_BODY,
                    g_param_spec_string ("body", NULL, "message body", 
                                         NULL, G_PARAM_READWRITE));

}

static void
ccnet_message_init (CcnetMessage *message)
{
}

CcnetMessage *
ccnet_message_new_full (const char *from,
                        const char *to,
                        const char *app,
                        const char *body,
                        time_t ctime,
                        time_t rcv_time,
                        const char *msg_id,
                        int flags)
{
    CcnetMessage *message;

    if (!from || !to || !app)
        return NULL;

    message = g_object_new (CCNET_TYPE_MESSAGE, NULL);

    message->flags = flags;
    memcpy (message->from, from, 40);
    message->from[40] = '\0';
    memcpy (message->to, to, 40);
    message->to[40] = '\0';
    message->app = g_strdup(app);
    message->body = g_strdup(body);
    message->ctime = (ctime ? ctime : time(NULL));
    message->rtime = rcv_time;
    message->id = (msg_id ? g_strdup (msg_id) : ccnet_util_gen_uuid());

    return message;
}

CcnetMessage *
ccnet_message_new (const char *from,
                   const char *to,
                   const char *app,
                   const char *body,
                   int flags)
{
    return ccnet_message_new_full (from, to, app, body, 0, 0, NULL, flags);
}

void
ccnet_message_free (CcnetMessage *message)
{
    g_object_unref (message);
}


void
ccnet_message_to_string_buf (CcnetMessage *msg, GString *buf)
{
    g_string_printf (buf, "%d %s %s %s %d %d %s %s", msg->flags,
                     msg->from, 
                     msg->to,
                     msg->id,
                     (int)msg->ctime,
                     (int)msg->rtime,
                     msg->app,
                     msg->body);
}

CcnetMessage *
ccnet_message_from_string (char *buf, int len)
{
    char flags;
    int is_group_msg;
    char *from_id, *to_id, *msg_id, *body, *p, *end, *app;
    int ctime, rcv_time = 0;
    CcnetMessage *message;

    g_return_val_if_fail (buf[len-1] == '\0', NULL);

    p = buf + 1;
    while (*p != ' ' && *p) ++p;
    if (*p != ' ')
        goto error;
    *p = '\0';
    flags = atoi (buf);
    is_group_msg = flags & FLAG_TO_GROUP;

    from_id = ++p;
    p += 40;
    g_return_val_if_fail (*p == ' ', NULL);
    *p = '\0';

    to_id = ++p;
    if (!is_group_msg)
        p += 40;                /* SHA-1 */
    else
        p += 36;                /* UUID */
    g_return_val_if_fail (*p == ' ', NULL);
    *p = '\0';

    msg_id = ++p;
    p += 36;
    g_return_val_if_fail (*p == ' ', NULL);
    *p++ = '\0';

    end = strchr (p, ' ');
    *end = '\0';
    ctime = atoi (p);

    p = end + 1;
    end = strchr (p, ' ');
    *end = '\0';
    rcv_time = atoi (p);

    p = app = end + 1;
    while (*p != ' ' && *p) ++p;
    if (*p != ' ')
        goto error;
    *p = '\0';
    body = p + 1;

    message = ccnet_message_new_full (from_id, to_id,
                                      app, body,
                                      ctime, rcv_time,
                                      msg_id, flags);
    return message;

error:
    return NULL;
}

gboolean
ccnet_message_is_to_group(CcnetMessage *msg)
{
    return msg->flags &  FLAG_TO_GROUP;
}

void
ccnet_message_body_take (CcnetMessage *msg, char *body)
{
    msg->body = body;
}

void
ccnet_message_body_dup (CcnetMessage *msg, char *body)
{
    msg->body = g_strdup (body);
}
