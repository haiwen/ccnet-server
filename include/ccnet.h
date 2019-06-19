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

/* mainloop */

void ccnet_main (CcnetClient *client);

typedef void (*RegisterServiceCB) (gboolean success);
void ccnet_register_service (CcnetClient *client,
                             const char *service, const char *group,
                             GType proc_type, RegisterServiceCB cb);
gboolean ccnet_register_service_sync (CcnetClient *client,
                                      const char *service,
                                      const char *group);
CcnetClient *ccnet_init (const char *central_config_dir, const char *confdir);

void ccnet_send_command (CcnetClient *client, const char *command,
                         SendcmdProcRcvrspCallback cmd_cb, void *cbdata);

/* client pool */

struct CcnetClientPool;
typedef struct CcnetClientPool CcnetClientPool;

CcnetClient *
ccnet_client_pool_get_client (struct CcnetClientPool *cpool);

void
ccnet_client_pool_return_client (struct CcnetClientPool *cpool,
                                 CcnetClient *client);

GList *ccnet_get_groups_by_user (SearpcClient *client, const char *user, int return_ancestors);
GList *ccnet_get_org_groups_by_user (SearpcClient *client, const char *user, int org_id);
GList *
ccnet_get_group_members (SearpcClient *client, int group_id);
int
ccnet_org_user_exists (SearpcClient *client, int org_id, const char *user);

#endif
