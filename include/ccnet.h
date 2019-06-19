/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef _CCNET_H
#define _CCNET_H

#include <ccnet/option.h>

#include <glib.h>

#include <ccnet/valid-check.h>
#include <ccnet/peer.h>
#include <ccnet/message.h>
#include <ccnet/status-code.h>
#include <ccnet/processor.h>

#include <ccnet/ccnet-session-base.h>
#include <ccnet/ccnet-client.h>

#include <ccnet/proc-factory.h>
#include <ccnet/sendcmd-proc.h>
#include <ccnet/mqclient-proc.h>
#include <ccnet/invoke-service-proc.h>

#include <ccnet/timer.h>

#include <searpc-client.h>

GList *ccnet_get_groups_by_user (SearpcClient *client, const char *user, int return_ancestors);
GList *ccnet_get_org_groups_by_user (SearpcClient *client, const char *user, int org_id);
GList *
ccnet_get_group_members (SearpcClient *client, int group_id);
int
ccnet_org_user_exists (SearpcClient *client, int org_id, const char *user);

#endif
