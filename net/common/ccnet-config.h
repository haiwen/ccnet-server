/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_CONFIG_H
#define SEAFILE_CONFIG_H

#include "session.h"
#include "db.h"

/*
 * Returns: config value in string. The string should be freed by caller. 
 */
char *
ccnet_session_config_get_string (CcnetSession *session,
                                 const char *key);

/*
 * Returns:
 * If key exists, @exists will be set to TRUE and returns the value;
 * otherwise, @exists will be set to FALSE and returns -1.
 */
int
ccnet_session_config_get_int (CcnetSession *session,
                              const char *key,
                              gboolean *exists);

int
ccnet_session_config_set_string (CcnetSession *session,
                                 const char *key,
                                 const char *value);

int
ccnet_session_config_set_int (CcnetSession *session,
                              const char *key,
                              int value);

sqlite3 *
ccnet_session_config_open_db (const char *ccnet_dir);

#endif
