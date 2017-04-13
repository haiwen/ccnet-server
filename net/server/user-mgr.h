/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_USER_MGR_H
#define CCNET_USER_MGR_H

#include <glib.h>
#include <glib-object.h>

#define CCNET_TYPE_USER_MANAGER                  (ccnet_user_manager_get_type ())
#define CCNET_USER_MANAGER(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_USER_MANAGER, CcnetUserManager))
#define CCNET_IS_USER_MANAGER(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_USER_MANAGER))
#define CCNET_USER_MANAGER_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_USER_MANAGER, CcnetUserManagerClass))
#define CCNET_IS_USER_MANAGER_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_USER_MANAGER))
#define CCNET_USER_MANAGER_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_USER_MANAGER, CcnetUserManagerClass))


typedef struct _CcnetUserManager CcnetUserManager;
typedef struct _CcnetUserManagerClass CcnetUserManagerClass;

typedef struct CcnetUserManagerPriv CcnetUserManagerPriv;


struct _CcnetUserManager
{
    GObject         parent_instance;

    CcnetSession   *session;
    
    char           *userdb_path;
    GHashTable     *user_hash;

#ifdef HAVE_LDAP
    /* LDAP related */
    gboolean        use_ldap;
    char           *ldap_host;
#ifdef WIN32
    gboolean        use_ssl;
#endif
    char           **base_list;  /* base DN from where all users can be reached */
    char           *filter;     /* Additional search filter */
    char           *user_dn;    /* DN of the admin user */
    char           *password;   /* password for admin user */
    char           *login_attr;  /* attribute name used for login */
#endif

    int passwd_hash_iter;

    CcnetUserManagerPriv *priv;
};

struct _CcnetUserManagerClass
{
    GObjectClass    parent_class;
};

GType ccnet_user_manager_get_type  (void);

CcnetUserManager* ccnet_user_manager_new (CcnetSession *);
int ccnet_user_manager_prepare (CcnetUserManager *manager);

void ccnet_user_manager_free (CcnetUserManager *manager);

void ccnet_user_manager_start (CcnetUserManager *manager);

void
ccnet_user_manager_set_max_users (CcnetUserManager *manager, gint64 max_users);

int
ccnet_user_manager_add_emailuser (CcnetUserManager *manager,
                                  const char *email,
                                  const char *encry_passwd,
                                  int is_staff, int is_active);

int
ccnet_user_manager_remove_emailuser (CcnetUserManager *manager,
                                     const char *source,
                                     const char *email);

int
ccnet_user_manager_validate_emailuser (CcnetUserManager *manager,
                                       const char *email,
                                       const char *passwd);

CcnetEmailUser*
ccnet_user_manager_get_emailuser (CcnetUserManager *manager, const char *email);

CcnetEmailUser*
ccnet_user_manager_get_emailuser_with_import (CcnetUserManager *manager,
                                              const char *email);
CcnetEmailUser*
ccnet_user_manager_get_emailuser_by_id (CcnetUserManager *manager, int id);

/*
 * @source: "DB" or "LDAP".
 * @status: "", "active", or "inactive". returns all users when this argument is "".
 */
GList*
ccnet_user_manager_get_emailusers (CcnetUserManager *manager,
                                   const char *source,
                                   int start, int limit,
                                   const char *status);

GList*
ccnet_user_manager_search_emailusers (CcnetUserManager *manager,
                                      const char *source,
                                      const char *keyword,
                                      int start, int limit);

GList*
ccnet_user_manager_search_ldapusers (CcnetUserManager *manager,
                                     const char *keyword,
                                     int start, int limit);

gint64
ccnet_user_manager_count_emailusers (CcnetUserManager *manager, const char *source);

gint64
ccnet_user_manager_count_inactive_emailusers (CcnetUserManager *manager, const char *source);

GList*
ccnet_user_manager_filter_emailusers_by_emails(CcnetUserManager *manager,
                                               const char *emails);

int
ccnet_user_manager_update_emailuser (CcnetUserManager *manager,
                                     const char *source,
                                     int id, const char* passwd,
                                     int is_staff, int is_active);

int
ccnet_user_manager_update_role_emailuser (CcnetUserManager *manager,
                                     const char* email, const char* role);

GList*
ccnet_user_manager_get_superusers(CcnetUserManager *manager);

int
ccnet_user_manager_add_binding (CcnetUserManager *manager, const char *email,
                                const char *peer_id);

/* Remove all bindings to an email */
int
ccnet_user_manager_remove_binding (CcnetUserManager *manager, const char *email);

/* Remove one specific peer-id binding to an email */
int
ccnet_user_manager_remove_one_binding (CcnetUserManager *manager,
                                       const char *email,
                                       const char *peer_id);

char *
ccnet_user_manager_get_binding_email (CcnetUserManager *manager, const char *peer_id);

GList *
ccnet_user_manager_get_binding_peerids (CcnetUserManager *manager, const char *email);

gint64
ccnet_user_manager_get_role_quota (CcnetUserManager *manager,
                                   const char *role);

int
ccnet_user_manager_set_role_quota (CcnetUserManager *manager,
                                   const char *role,
                                   gint64 quota);

#endif
