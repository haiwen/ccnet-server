/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "server-session.h"

#include "ccnet-db.h"
#include "group-mgr.h"
#include "org-mgr.h"

#include "utils.h"
#include "log.h"

extern CcnetSession *session;

struct _CcnetGroupManagerPriv {
    CcnetDB	*db;
    const char *table_name;
};

static int open_db (CcnetGroupManager *manager);
static int check_db_table (CcnetGroupManager *manager, CcnetDB *db);

CcnetGroupManager* ccnet_group_manager_new (CcnetSession *session)
{
    CcnetGroupManager *manager = g_new0 (CcnetGroupManager, 1);

    manager->session = session;
    manager->priv = g_new0 (CcnetGroupManagerPriv, 1);

    return manager;
}

int
ccnet_group_manager_prepare (CcnetGroupManager *manager)
{
    if (!g_key_file_has_key (manager->session->keyf, "GROUP", "TABLE_NAME", NULL))
        manager->priv->table_name = g_strdup ("Group");
    else
        manager->priv->table_name = g_key_file_get_string (manager->session->keyf, "GROUP", "TABLE_NAME", NULL);

    return open_db(manager);
}

void ccnet_group_manager_start (CcnetGroupManager *manager)
{
}

static CcnetDB *
open_sqlite_db (CcnetGroupManager *manager)
{
    CcnetDB *db = NULL;
    char *db_dir;
    char *db_path;

    db_dir = g_build_filename (manager->session->config_dir, "GroupMgr", NULL);
    if (checkdir_with_mkdir(db_dir) < 0) {
        ccnet_error ("Cannot open db dir %s: %s\n", db_dir,
                     strerror(errno));
        g_free (db_dir);
        return NULL;
    }
    g_free (db_dir);

    db_path = g_build_filename (manager->session->config_dir, "GroupMgr",
                                "groupmgr.db", NULL);
    db = ccnet_db_new_sqlite (db_path);

    g_free (db_path);

    return db;
}

static int
open_db (CcnetGroupManager *manager)
{
    CcnetDB *db = NULL;

    switch (ccnet_db_type(manager->session->db)) {
    case CCNET_DB_TYPE_SQLITE:
        db = open_sqlite_db (manager);
        break;
    case CCNET_DB_TYPE_PGSQL:
    case CCNET_DB_TYPE_MYSQL:
        db = manager->session->db;
        break;
    }

    if (!db)
        return -1;
    
    manager->priv->db = db;
    return check_db_table (manager, db);
}

/* -------- Group Database Management ---------------- */

static int check_db_table (CcnetGroupManager *manager, CcnetDB *db)
{
    char *sql;
    GString *group_sql = g_string_new ("");
    const char *table_name = manager->priv->table_name;

    int db_type = ccnet_db_type (db);
    if (db_type == CCNET_DB_TYPE_MYSQL) {
        g_string_printf (group_sql,
            "CREATE TABLE IF NOT EXISTS `%s` (`group_id` INTEGER"
            " PRIMARY KEY AUTO_INCREMENT, `group_name` VARCHAR(255),"
            " `creator_name` VARCHAR(255), `timestamp` BIGINT,"
            " `type` VARCHAR(32), `parent_group_id` INTEGER)"
            "ENGINE=INNODB", table_name);
        if (ccnet_db_query (db, group_sql->str) < 0) {
            g_string_free (group_sql, TRUE);
            return -1;
        }

        sql = "CREATE TABLE IF NOT EXISTS `GroupUser` (`group_id` INTEGER,"
            " `user_name` VARCHAR(255), `is_staff` tinyint, PRIMARY KEY"
            " (`group_id`, `user_name`), INDEX (`user_name`))"
            "ENGINE=INNODB";
        if (ccnet_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS GroupDNPair (group_id INTEGER,"
            " dn VARCHAR(255))ENGINE=INNODB";
        if (ccnet_db_query (db, sql) < 0)
            return -1;
    } else if (db_type == CCNET_DB_TYPE_SQLITE) {
        g_string_printf (group_sql,
            "CREATE TABLE IF NOT EXISTS `%s` (`group_id` INTEGER"
            " PRIMARY KEY AUTOINCREMENT, `group_name` VARCHAR(255),"
            " `creator_name` VARCHAR(255), `timestamp` BIGINT,"
            " `type` VARCHAR(32))", table_name);
        if (ccnet_db_query (db, group_sql->str) < 0) {
            g_string_free (group_sql, TRUE);
            return -1;
        }

        sql = "CREATE TABLE IF NOT EXISTS `GroupUser` (`group_id` INTEGER, "
            "`user_name` VARCHAR(255), `is_staff` tinyint)";
        if (ccnet_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS groupid_username_indx on "
            "`GroupUser` (`group_id`, `user_name`)";
        if (ccnet_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE INDEX IF NOT EXISTS username_indx on "
            "`GroupUser` (`user_name`)";
        if (ccnet_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS GroupDNPair (group_id INTEGER,"
            " dn VARCHAR(255))";
        if (ccnet_db_query (db, sql) < 0)
            return -1;
    } else if (db_type == CCNET_DB_TYPE_PGSQL) {
        g_string_printf (group_sql,
            "CREATE TABLE IF NOT EXISTS \"%s\" (group_id SERIAL"
            " PRIMARY KEY, group_name VARCHAR(255),"
            " creator_name VARCHAR(255), timestamp BIGINT,"
            " type VARCHAR(32))", table_name);
        if (ccnet_db_query (db, group_sql->str) < 0) {
            g_string_free (group_sql, TRUE);
            return -1;
        }

        sql = "CREATE TABLE IF NOT EXISTS GroupUser (group_id INTEGER,"
            " user_name VARCHAR(255), is_staff smallint, UNIQUE "
            " (group_id, user_name))";
        if (ccnet_db_query (db, sql) < 0)
            return -1;

        if (!pgsql_index_exists (db, "groupuser_username_idx")) {
            sql = "CREATE INDEX groupuser_username_idx ON GroupUser (user_name)";
            if (ccnet_db_query (db, sql) < 0)
                return -1;
        }

        sql = "CREATE TABLE IF NOT EXISTS GroupDNPair (group_id INTEGER,"
            " dn VARCHAR(255))";
        if (ccnet_db_query (db, sql) < 0)
            return -1;
    }
    g_string_free (group_sql, TRUE);

    return 0;
}

static int
create_group_common (CcnetGroupManager *mgr,
                     const char *group_name,
                     const char *user_name,
                     int parent_group_id,
                     GError **error)
{
    CcnetDB *db = mgr->priv->db;
    gint64 now = get_current_time();
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;
    int group_id = -1;

    char *user_name_l = g_ascii_strdown (user_name, -1);
    
    if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL)
        g_string_printf (sql,
            "INSERT INTO \"%s\"(group_name, "
            "creator_name, timestamp, parent_group_id) VALUES(?, ?, ?, ?)", table_name);
    else
        g_string_printf (sql,
            "INSERT INTO `%s`(group_name, "
            "creator_name, timestamp, parent_group_id) VALUES(?, ?, ?, ?)", table_name);

    if (ccnet_db_statement_query (db, sql->str, 4,
                                  "string", group_name, "string", user_name_l,
                                  "int64", now, "int", parent_group_id) < 0) {
        g_set_error (error, CCNET_DOMAIN, 0, "Failed to create group");
        goto out;
    }

    if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL)
        g_string_printf (sql,
            "SELECT group_id FROM \"%s\" WHERE "
            "group_name = ? AND creator_name = ? "
            "AND timestamp = ?", table_name);
    else
        g_string_printf (sql,
            "SELECT group_id FROM `%s` WHERE "
            "group_name = ? AND creator_name = ? "
            "AND timestamp = ?", table_name);

    group_id = ccnet_db_statement_get_int (db, sql->str, 3,
                                           "string", group_name, "string", user_name_l,
                                           "int64", now);
    if (group_id < 0) {
        g_set_error (error, CCNET_DOMAIN, 0, "Failed to create group");
        goto out;
    }

    g_string_printf (sql, "INSERT INTO GroupUser VALUES (?, ?, ?)");

    if (ccnet_db_statement_query (db, sql->str, 3,
                                  "int", group_id, "string", user_name_l,
                                  "int", 1) < 0) {
        if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL)
            g_string_printf (sql, "DELETE FROM \"%s\" WHERE group_id=?", table_name);
        else
            g_string_printf (sql, "DELETE FROM `%s` WHERE group_id=?", table_name);
        ccnet_db_statement_query (db, sql->str, 1, "int", group_id);
        g_set_error (error, CCNET_DOMAIN, 0, "Failed to create group");
        group_id = -1;
        goto out;
    }

out:
    g_string_free (sql, TRUE);
    g_free (user_name_l);
    return group_id;
}

int ccnet_group_manager_create_group (CcnetGroupManager *mgr,
                                      const char *group_name,
                                      const char *user_name,
                                      int parent_group_id,
                                      GError **error)
{
    return create_group_common (mgr, group_name, user_name, parent_group_id, error);
}

/* static gboolean */
/* duplicate_org_group_name (CcnetGroupManager *mgr, */
/*                           int org_id, */
/*                           const char *group_name) */
/* { */
/*     GList *org_groups = NULL, *ptr; */
/*     CcnetOrgManager *org_mgr = ((CcnetServerSession *)(mgr->session))->org_mgr; */
    
/*     org_groups = ccnet_org_manager_get_org_groups (org_mgr, org_id, -1, -1); */
/*     if (!org_groups) */
/*         return FALSE; */

/*     for (ptr = org_groups; ptr; ptr = ptr->next) { */
/*         int group_id = (int)(long)ptr->data; */
/*         CcnetGroup *group = ccnet_group_manager_get_group (mgr, group_id, */
/*                                                            NULL); */
/*         if (!group) */
/*             continue; */

/*         if (g_strcmp0 (group_name, ccnet_group_get_group_name(group)) == 0) { */
/*             g_list_free (org_groups); */
/*             g_object_unref (group); */
/*             return TRUE; */
/*         } else { */
/*             g_object_unref (group); */
/*         } */
/*     } */

/*     g_list_free (org_groups); */
/*     return FALSE; */
/* } */

int ccnet_group_manager_create_org_group (CcnetGroupManager *mgr,
                                          int org_id,
                                          const char *group_name,
                                          const char *user_name,
                                          int parent_group_id,
                                          GError **error)
{
    CcnetOrgManager *org_mgr = ((CcnetServerSession *)(mgr->session))->org_mgr;
    
    /* if (duplicate_org_group_name (mgr, org_id, group_name)) { */
    /*     g_set_error (error, CCNET_DOMAIN, 0, */
    /*                  "The group has already created in this org."); */
    /*     return -1; */
    /* } */

    int group_id = create_group_common (mgr, group_name, user_name, parent_group_id, error);
    if (group_id < 0) {
        g_set_error (error, CCNET_DOMAIN, 0, "Failed to create org group.");
        return -1;
    }

    if (ccnet_org_manager_add_org_group (org_mgr, org_id, group_id,
                                         error) < 0) {
        g_set_error (error, CCNET_DOMAIN, 0, "Failed to create org group.");
        return -1;
    }

    return group_id;
}

static gboolean
check_group_staff (CcnetDB *db, int group_id, const char *user_name)
{
    return ccnet_db_statement_exists (db, "SELECT group_id FROM GroupUser WHERE "
                                      "group_id = ? AND user_name = ? AND "
                                      "is_staff = 1",
                                      2, "int", group_id, "string", user_name);
}

int ccnet_group_manager_remove_group (CcnetGroupManager *mgr,
                                      int group_id,
                                      gboolean remove_anyway,
                                      GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GString *sql = g_string_new ("");
    gboolean exists;
    const char *table_name = mgr->priv->table_name;

    /* No permission check here, since both group staff and seahub staff
     * can remove group.
     */
     if (remove_anyway != TRUE) {
        if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL)
            g_string_printf (sql, "SELECT 1 FROM \"%s\" WHERE parent_group_id=?", table_name);
        else
            g_string_printf (sql, "SELECT 1 FROM `%s` WHERE parent_group_id=?", table_name);
        exists = ccnet_db_statement_exists (db, sql->str, 1, "int", group_id);
        if (exists) {
            ccnet_warning ("Failed to remove group [%d] whose child group must be removed first.\n", group_id);
            g_string_free (sql, TRUE);
            return -1;
        }
     }
    
    if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL)
        g_string_printf (sql, "DELETE FROM \"%s\" WHERE group_id=?", table_name);
    else
        g_string_printf (sql, "DELETE FROM `%s` WHERE group_id=?", table_name);
    ccnet_db_statement_query (db, sql->str, 1, "int", group_id);

    g_string_printf (sql, "DELETE FROM GroupUser WHERE group_id=?");
    ccnet_db_statement_query (db, sql->str, 1, "int", group_id);

    g_string_free (sql, TRUE);
    
    return 0;
}

static gboolean
check_group_exists (CcnetGroupManager *mgr, CcnetDB *db, int group_id)
{
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;
    gboolean exists;

    if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL) {
        g_string_printf (sql, "SELECT group_id FROM \"%s\" WHERE group_id=?", table_name);
        exists = ccnet_db_statement_exists (db, sql->str, 1, "int", group_id);
    } else {
        g_string_printf (sql, "SELECT group_id FROM `%s` WHERE group_id=?", table_name);
        exists = ccnet_db_statement_exists (db, sql->str, 1, "int", group_id);
    }
    g_string_free (sql, TRUE);

    return exists;
}

int ccnet_group_manager_add_member (CcnetGroupManager *mgr,
                                    int group_id,
                                    const char *user_name,
                                    const char *member_name,
                                    GError **error)
{
    CcnetDB *db = mgr->priv->db;

    /* check whether user is the staff of the group */
    if (!check_group_staff (db, group_id, user_name)) {
        g_set_error (error, CCNET_DOMAIN, 0,
                     "Permission error: only group staff can add member");
        return -1; 
    }    

    /* check whether group exists */
    if (!check_group_exists (mgr, db, group_id)) {
        g_set_error (error, CCNET_DOMAIN, 0, "Group not exists");
        return -1;
    }

    /* check whether group is full */
    /* snprintf (sql, sizeof(sql), "SELECT count(group_id) FROM `GroupUser` " */
    /*           "WHERE `group_id` = %d", group_id); */
    /* int count = ccnet_db_get_int (db, sql); */
    /* if (count >= MAX_GROUP_MEMBERS) { */
    /*     g_set_error (error, CCNET_DOMAIN, 0, "Group is full"); */
    /*     return -1; */
    /* } */

    char *member_name_l = g_ascii_strdown (member_name, -1);
    int rc = ccnet_db_statement_query (db, "INSERT INTO GroupUser VALUES (?, ?, ?)",
                                       3, "int", group_id, "string", member_name_l,
                                       "int", 0);
    g_free (member_name_l);
    if (rc < 0) {
        g_set_error (error, CCNET_DOMAIN, 0, "Failed to add member to group");
        return -1;
    }

    return 0;
}

int ccnet_group_manager_remove_member (CcnetGroupManager *mgr,
                                       int group_id,
                                       const char *user_name,
                                       const char *member_name,
                                       GError **error)
{
    CcnetDB *db = mgr->priv->db;
    char *sql;

    /* check whether user is the staff of the group */
    if (!check_group_staff (db, group_id, user_name)) {
        g_set_error (error, CCNET_DOMAIN, 0,
                     "Only group staff can remove member");
        return -1; 
    }    

    /* check whether group exists */
    if (!check_group_exists (mgr, db, group_id)) {
        g_set_error (error, CCNET_DOMAIN, 0, "Group not exists");
        return -1;
    }

    /* can not remove myself */
    if (g_strcmp0 (user_name, member_name) == 0) {
        g_set_error (error, CCNET_DOMAIN, 0, "Can not remove myself");
        return -1;
    }

    sql = "DELETE FROM GroupUser WHERE group_id=? AND user_name=?";
    ccnet_db_statement_query (db, sql, 2, "int", group_id, "string", member_name);

    return 0;
}

int ccnet_group_manager_set_admin (CcnetGroupManager *mgr,
                                   int group_id,
                                   const char *member_name,
                                   GError **error)
{
    CcnetDB *db = mgr->priv->db;

    ccnet_db_statement_query (db,
                              "UPDATE GroupUser SET is_staff = 1 "
                              "WHERE group_id = ? and user_name = ?",
                              2, "int", group_id, "string", member_name);

    return 0;
}

int ccnet_group_manager_unset_admin (CcnetGroupManager *mgr,
                                     int group_id,
                                     const char *member_name,
                                     GError **error)
{
    CcnetDB *db = mgr->priv->db;

    ccnet_db_statement_query (db,
                              "UPDATE GroupUser SET is_staff = 0 "
                              "WHERE group_id = ? and user_name = ?",
                              2, "int", group_id, "string", member_name);

    return 0;
}

int ccnet_group_manager_set_group_name (CcnetGroupManager *mgr,
                                        int group_id,
                                        const char *group_name,
                                        GError **error)
{
    const char *table_name = mgr->priv->table_name;
    GString *sql = g_string_new ("");
    CcnetDB *db = mgr->priv->db;

    if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL) {
        g_string_printf (sql, "UPDATE \"%s\" SET group_name = ? "
                              "WHERE group_id = ?", table_name);
        ccnet_db_statement_query (db, sql->str, 2, "string", group_name, "int", group_id);
    } else {
        g_string_printf (sql, "UPDATE `%s` SET group_name = ? "
                              "WHERE group_id = ?", table_name);
        ccnet_db_statement_query (db, sql->str, 2, "string", group_name, "int", group_id);
    }
    g_string_free (sql, TRUE);

    return 0;
}

int ccnet_group_manager_quit_group (CcnetGroupManager *mgr,
                                    int group_id,
                                    const char *user_name,
                                    GError **error)
{
    CcnetDB *db = mgr->priv->db;
    
    /* check where user is the staff of the group */
    if (check_group_staff (db, group_id, user_name)) {
        g_set_error (error, CCNET_DOMAIN, 0,
                     "Group staff can not quit group");
        return -1; 
    }    

    /* check whether group exists */
    if (!check_group_exists (mgr, db, group_id)) {
        g_set_error (error, CCNET_DOMAIN, 0, "Group not exists");
        return -1;
    }

    ccnet_db_statement_query (db,
                              "DELETE FROM GroupUser WHERE group_id=? "
                              "AND user_name=?",
                              2, "int", group_id, "string", user_name);

    return 0;
}

static gboolean
get_all_child_groups_cb (CcnetDBRow *row, void *data)
{
    GList **plist = data;
    CcnetGroup *group;

    int group_id = ccnet_db_row_get_column_int (row, 0);
    const char *group_name = ccnet_db_row_get_column_text (row, 1);
    const char *creator_name = ccnet_db_row_get_column_text (row, 2);
    gint64 ts = ccnet_db_row_get_column_int64 (row, 3);
    int parent_group_id = ccnet_db_row_get_column_int (row, 4);

    group = g_object_new (CCNET_TYPE_GROUP,
                          "id", group_id,
                          "group_name", group_name,
                          "creator_name", creator_name,
                          "timestamp", ts,
                          "source", "DB",
                          "parent_group_id", parent_group_id,
                          NULL);

    *plist = g_list_append (*plist, group);

    return TRUE;
}

GList *
ccnet_group_manager_get_all_child_groups (CcnetGroupManager *mgr,
                                          int group_id)
{
    GList *ret = NULL, *tmp_list = NULL, *ptr;
    CcnetDB *db = mgr->priv->db;
    GString *sql = g_string_new ("");
    CcnetGroup *group;
    const char *table_name = mgr->priv->table_name;

    if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL)
        g_string_printf (sql, "SELECT group_id, group_name, creator_name, timestamp, parent_group_id FROM "
                              "\"%s\" WHERE parent_group_id=?",
                              table_name);
    else
        g_string_printf (sql, "SELECT group_id, group_name, creator_name, timestamp, parent_group_id FROM "
                              "`%s` WHERE parent_group_id=?",
                              table_name);

    if (ccnet_db_statement_foreach_row (db,
                                        sql->str,
                                        get_all_child_groups_cb, &tmp_list,
                                        1, "int", group_id) < 0) {
        g_string_free (sql, TRUE);
        return NULL;
    }
    g_string_free (sql, TRUE);

    for (ptr = tmp_list; ptr; ptr = ptr->next) {
        group = ptr->data;
        ret = g_list_append (ret, group);

        int tmp_group_id;
        g_object_get (group, "id", &tmp_group_id, NULL);
        GList *child_list = ccnet_group_manager_get_all_child_groups(mgr, tmp_group_id);
        ret = g_list_concat (ret, child_list);
    }
    
    return ret;
}

GList *
ccnet_group_manager_get_all_parent_groups (CcnetGroupManager *mgr, int group_id)
{
    GList *ret = NULL;
    CcnetGroup *group = NULL;

    while (group_id > 0) {
        group = ccnet_group_manager_get_group (mgr, group_id, NULL);
        if (group) {
            ret = g_list_prepend (ret, group);
            g_object_get(group, "parent_group_id", &group_id, NULL);
        } else {
            break;
        }
    }

    return ret;
}

static gboolean
get_user_groups_cb (CcnetDBRow *row, void *data)
{
    GList **plist = data;
    CcnetGroup *group, *end_flag;
    CcnetGroupManager *group_mgr = ((CcnetServerSession *)session)->group_mgr;

    int group_id = ccnet_db_row_get_column_int (row, 0);
    const char *group_name = ccnet_db_row_get_column_text (row, 1);
    const char *creator_name = ccnet_db_row_get_column_text (row, 2);
    gint64 ts = ccnet_db_row_get_column_int64 (row, 3);
    int parent_group_id = ccnet_db_row_get_column_int (row, 4);

    group = g_object_new (CCNET_TYPE_GROUP,
                          "id", group_id,
                          "group_name", group_name,
                          "creator_name", creator_name,
                          "timestamp", ts,
                          "source", "DB",
                          "parent_group_id", parent_group_id,
                          "is_direct", TRUE,
                          NULL);

    /* Get all parent groups */
    GList *parent_list = ccnet_group_manager_get_all_parent_groups(group_mgr, parent_group_id);

    /* Get all child groups */
    GList *child_list = ccnet_group_manager_get_all_child_groups(group_mgr, group_id);

    parent_list = g_list_append (parent_list, group);
    parent_list = g_list_concat (parent_list, child_list);
    end_flag = g_object_new (CCNET_TYPE_GROUP,
                             "id", -1, NULL);
    parent_list = g_list_append (parent_list, end_flag);
    
    *plist = g_list_concat (*plist, parent_list);

    return TRUE;
}

GList *
ccnet_group_manager_get_groups_by_user (CcnetGroupManager *mgr,
                                        const char *user_name,
                                        GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GList *groups = NULL;
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;

    if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL)
        g_string_printf (sql, 
            "SELECT g.group_id, group_name, creator_name, timestamp, parent_group_id FROM "
            "\"%s\" g, GroupUser u WHERE g.group_id = u.group_id AND user_name=?",
            table_name);
    else
        g_string_printf (sql,
            "SELECT g.group_id, group_name, creator_name, timestamp, parent_group_id FROM "
            "`%s` g, GroupUser u WHERE g.group_id = u.group_id AND user_name=?",
            table_name);

    if (ccnet_db_statement_foreach_row (db,
                                        sql->str,
                                        get_user_groups_cb, &groups,
                                        1, "string", user_name) < 0) {
        g_string_free (sql, TRUE);
        return NULL;
    }
    g_string_free (sql, TRUE);

    return groups;
}

static gboolean
get_ccnetgroup_cb (CcnetDBRow *row, void *data)
{
    CcnetGroup **p_group = data;
    int group_id;
    const char *group_name;
    const char *creator;
    int parent_group_id;
    gint64 ts;
    
    group_id = ccnet_db_row_get_column_int (row, 0);
    group_name = (const char *)ccnet_db_row_get_column_text (row, 1);
    creator = (const char *)ccnet_db_row_get_column_text (row, 2);
    ts = ccnet_db_row_get_column_int64 (row, 3);
    parent_group_id = ccnet_db_row_get_column_int (row, 4);

    char *creator_l = g_ascii_strdown (creator, -1);
    *p_group = g_object_new (CCNET_TYPE_GROUP,
                             "id", group_id,
                             "group_name", group_name,
                             "creator_name", creator_l,
                             "timestamp", ts,
                             "source", "DB",
                             "parent_group_id", parent_group_id,
                             NULL);
    g_free (creator_l);

    return FALSE;
}

CcnetGroup *
ccnet_group_manager_get_group (CcnetGroupManager *mgr, int group_id,
                               GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GString *sql = g_string_new ("");
    CcnetGroup *ccnetgroup = NULL;
    const char *table_name = mgr->priv->table_name;

    if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL)
        g_string_printf (sql,
            "SELECT group_id, group_name, creator_name, timestamp, parent_group_id FROM "
            "\"%s\" WHERE group_id = ?", table_name);
    else
        g_string_printf (sql,
            "SELECT group_id, group_name, creator_name, timestamp, parent_group_id FROM "
            "`%s` WHERE group_id = ?", table_name);
    if (ccnet_db_statement_foreach_row (db, sql->str,
                                        get_ccnetgroup_cb, &ccnetgroup,
                                        1, "int", group_id) < 0) {
        g_string_free (sql, TRUE);
        return NULL;
    }
    g_string_free (sql, TRUE);

    return ccnetgroup;
}

static gboolean
get_ccnet_groupuser_cb (CcnetDBRow *row, void *data)
{
    GList **plist = data;
    CcnetGroupUser *group_user;
    
    int group_id = ccnet_db_row_get_column_int (row, 0);
    const char *user = (const char *)ccnet_db_row_get_column_text (row, 1);
    int is_staff = ccnet_db_row_get_column_int (row, 2);

    char *user_l = g_ascii_strdown (user, -1);
    group_user = g_object_new (CCNET_TYPE_GROUP_USER,
                               "group_id", group_id,
                               "user_name", user_l,
                               "is_staff", is_staff,
                               NULL);
    g_free (user_l);
    if (group_user != NULL) {
        *plist = g_list_prepend (*plist, group_user);
    }
    
    return TRUE;
}

GList *
ccnet_group_manager_get_group_members (CcnetGroupManager *mgr, int group_id,
                                       GError **error)
{
    CcnetDB *db = mgr->priv->db;
    char *sql;
    GList *group_users = NULL;
    
    sql = "SELECT group_id, user_name, is_staff FROM GroupUser WHERE group_id = ?";
    if (ccnet_db_statement_foreach_row (db, sql,
                                        get_ccnet_groupuser_cb, &group_users,
                                        1, "int", group_id) < 0)
        return NULL;

    return g_list_reverse (group_users);
}

int
ccnet_group_manager_check_group_staff (CcnetGroupManager *mgr,
                                       int group_id,
                                       const char *user_name)
{
    return check_group_staff (mgr->priv->db, group_id, user_name);
}

int
ccnet_group_manager_remove_group_user (CcnetGroupManager *mgr,
                                       const char *user)
{
    CcnetDB *db = mgr->priv->db;

    ccnet_db_statement_query (db,
                              "DELETE FROM GroupUser "
                              "WHERE user_name = ?",
                              1, "string", user);

    return 0;
}

int
ccnet_group_manager_is_group_user (CcnetGroupManager *mgr,
                                   int group_id,
                                   const char *user)
{
    CcnetDB *db = mgr->priv->db;

    return ccnet_db_statement_exists (db, "SELECT group_id FROM GroupUser "
                                      "WHERE group_id=? AND user_name=?",
                                      2, "int", group_id, "string", user);
}

static gboolean
get_all_ccnetgroups_cb (CcnetDBRow *row, void *data)
{
    GList **plist = data;
    int group_id;
    const char *group_name;
    const char *creator;
    gint64 ts;

    group_id = ccnet_db_row_get_column_int (row, 0);
    group_name = (const char *)ccnet_db_row_get_column_text (row, 1);
    creator = (const char *)ccnet_db_row_get_column_text (row, 2);
    ts = ccnet_db_row_get_column_int64 (row, 3);

    char *creator_l = g_ascii_strdown (creator, -1);
    CcnetGroup *group = g_object_new (CCNET_TYPE_GROUP,
                                      "id", group_id,
                                      "group_name", group_name,
                                      "creator_name", creator_l,
                                      "timestamp", ts,
                                      "source", "DB",
                                      NULL);
    g_free (creator_l);

    *plist = g_list_prepend (*plist, group);
    
    return TRUE;
}

GList*
ccnet_group_manager_get_all_groups (CcnetGroupManager *mgr,
                                    int start, int limit, GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GList *ret = NULL;
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;
    int rc;

    if (ccnet_db_type(mgr->priv->db) == CCNET_DB_TYPE_PGSQL) {
        if (start == -1 && limit == -1) {
            g_string_printf (sql, "SELECT group_id, group_name, "
                                  "creator_name, timestamp FROM \"%s\" "
                                  "ORDER BY timestamp DESC", table_name);
            rc = ccnet_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 0);
        } else {
            g_string_printf (sql, "SELECT group_id, group_name, "
                                  "creator_name, timestamp FROM \"%s\" "
                                  "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                                  table_name);
            rc = ccnet_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 2, "int", limit, "int", start);
        }
    } else {
        if (start == -1 && limit == -1) {
            g_string_printf (sql, "SELECT `group_id`, `group_name`, "
                                  "`creator_name`, `timestamp` FROM `%s` "
                                  "ORDER BY timestamp DESC", table_name);
            rc = ccnet_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 0);
        } else {
            g_string_printf (sql, "SELECT `group_id`, `group_name`, "
                                  "`creator_name`, `timestamp` FROM `%s` "
                                  "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                                  table_name);
            rc = ccnet_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 2, "int", limit, "int", start);
        }
    }
    g_string_free (sql, TRUE);

    if (rc < 0)
        return NULL;

    return g_list_reverse (ret);
}

int
ccnet_group_manager_set_group_creator (CcnetGroupManager *mgr,
                                       int group_id,
                                       const char *user_name)
{
    CcnetDB *db = mgr->priv->db;
    const char *table_name = mgr->priv->table_name;
    GString *sql = g_string_new ("");

    if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL) {
        g_string_printf (sql, "UPDATE \"%s\" SET creator_name = ? WHERE group_id = ?",
                         table_name);
    } else {
        g_string_printf (sql, "UPDATE `%s` SET creator_name = ? WHERE group_id = ?",
                         table_name);
    }

    ccnet_db_statement_query (db, sql->str, 2, "string", user_name, "int", group_id);
    g_string_free (sql, TRUE);

    return 0;
    
}

GList *
ccnet_group_manager_search_groups (CcnetGroupManager *mgr,
                                   const char *keyword,
                                   int start, int limit)
{
    CcnetDB *db = mgr->priv->db;
    GList *ret = NULL;
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;

    int rc;
    char *db_patt = g_strdup_printf ("%%%s%%", keyword);

    if (ccnet_db_type(db) == CCNET_DB_TYPE_PGSQL) {
        if (start == -1 && limit == -1) {
            g_string_printf (sql,
                             "SELECT group_id, group_name, "
                             "creator_name, timestamp "
                             "FROM \"%s\" WHERE group_name LIKE ?", table_name);
            rc = ccnet_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 1, "string", db_patt);
        } else {
            g_string_printf (sql,
                             "SELECT group_id, group_name, "
                             "creator_name, timestamp "
                             "FROM \"%s\" WHERE group_name LIKE ? "
                             "LIMIT ? OFFSET ?", table_name);
            rc = ccnet_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 3, "string", db_patt,
                                                 "int", limit, "int", start);
        }
    } else {
        if (start == -1 && limit == -1) {
            g_string_printf (sql,
                             "SELECT group_id, group_name, "
                             "creator_name, timestamp "
                             "FROM `%s` WHERE group_name LIKE ?", table_name);
            rc = ccnet_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 1, "string", db_patt);
        } else {
            g_string_printf (sql,
                             "SELECT group_id, group_name, "
                             "creator_name, timestamp "
                             "FROM `%s` WHERE group_name LIKE ? "
                             "LIMIT ? OFFSET ?", table_name);
            rc = ccnet_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 3, "string", db_patt,
                                                 "int", limit, "int", start);
        }
    }
    g_free (db_patt);
    g_string_free (sql, TRUE);

    if (rc < 0) {
        while (ret != NULL) {
            g_object_unref (ret->data);
            ret = g_list_delete_link (ret, ret);
        }
        return NULL;
    }

    return g_list_reverse (ret);
}
