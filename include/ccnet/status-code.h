/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef STATUS_CODE_H
#define STATUS_CODE_H

/* SC: Status Code. SS: Status String */

/* Error Code for use in GError */
#define EC_NETWORK_ERR 1
#define ES_NETWORK_ERR "Network Error"


#define SC_PROC_KEEPALIVE "100"
#define SS_PROC_KEEPALIVE "processor keep alive"
#define SC_PROC_ALIVE "101"
#define SS_PROC_ALIVE "processor is alive"
#define SC_PROC_DEAD "102"
#define SS_PROC_DEAD "processor is dead"
#define SC_PROC_DONE  "103"
#define SS_PROC_DONE  "service is done"


#define SC_OK "200"
#define SS_OK "OK"
#define SC_PERM_CHECKING "250"
#define SS_PERM_CHECKING "Permission Checking"


#define SC_SHUTDOWN "500"
#define SS_SHUTDOWN "Shutdown"
#define SC_CREATE_PROC_ERR "501"
#define SS_CREATE_PROC_ERR "Create Processor Error"
#define SC_BAD_PEER "502"
#define SS_BAD_PEER "Bad peer id"
#define SC_BAD_USER "502"
#define SS_BAD_USER "Bad user id"
#define SC_BAD_ARGS "503"
#define SS_BAD_ARGS "Bad arguments"
#define SC_PERM_ERR "504"
#define SS_PERM_ERR "Permission Error"
#define SC_BAD_UPDATE_CODE  "506"
#define SS_BAD_UPDATE_CODE  "Bad update code"
#define SC_BAD_RESPONSE_CODE  "507"
#define SS_BAD_RESPONSE_CODE  "Bad response code"
#define SC_VERSION_MISMATCH "508"
#define SS_VERSION_MISMATCH "Version Mismatch"
#define SC_UNKNOWN_PEER "510"
#define SS_UNKNOWN_PEER "Unknown peer"
#define SC_UNKNOWN_SERVICE "511"
#define SS_UNKNOWN_SERVICE "Unknown service"
#define SC_UNKNOWN_SERVICE_IN_PERM "511"
#define SS_UNKNOWN_SERVICE_IN_PERM "Unknown service in permission check"
#define SC_PEER_UNREACHABLE "512"
#define SS_PEER_UNREACHABLE "Peer Unreachable"
#define SC_CON_TIMEOUT "513"
#define SS_CON_TIMEOUT "connection timeout"
#define SC_KEEPALIVE_TIMEOUT "514"
#define SS_KEEPALIVE_TIMEOUT "keepalive timeout"
#define SC_NETDOWN "515"
#define SS_NETDOWN "peer down"
#define SC_SERV_EXISTED "516"
#define SS_SERV_EXISTED "The service existed"

#endif
