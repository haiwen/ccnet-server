/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "include.h"

#include <ccnet.h>
#include <ccnet-object.h>
#include <searpc-client.h>

GList *
ccnet_get_groups_by_user (SearpcClient *client, const char *user, int return_ancestors)
{
    if (!user)
        return NULL;

    return searpc_client_call__objlist (
        client, "get_groups", CCNET_TYPE_GROUP, NULL,
        2, "string", user, "int", return_ancestors);
}

GList *
ccnet_get_org_groups_by_user (SearpcClient *client, const char *user, int org_id)
{
    if (!user)
        return NULL;

    return searpc_client_call__objlist (
        client, "get_org_groups_by_user", CCNET_TYPE_GROUP, NULL,
        2, "string", user, "int", org_id);
}

GList *
ccnet_get_group_members (SearpcClient *client, int group_id)
{
    return searpc_client_call__objlist (
        client, "get_group_members", CCNET_TYPE_GROUP_USER, NULL,
        1, "int", group_id);
}

int
ccnet_org_user_exists (SearpcClient *client, int org_id, const char *user)
{
    return searpc_client_call__int (client, "org_user_exists", NULL,
                                    2, "int", org_id, "string", user);
}
