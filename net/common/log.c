/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdio.h>
#include <glib.h>
#include <string.h>

#include "log.h"
#include "utils.h"

#include "session.h"

#include "message.h"
#include "message-manager.h"

extern CcnetSession  *session;

/* message with greater log levels will be ignored */
static int ccnet_log_level;
static char *logfile;
static FILE *logfp;

static void 
ccnet_log (const gchar *log_domain, GLogLevelFlags log_level,
           const gchar *message,    gpointer user_data)
{
    time_t t;
    struct tm *tm;
    char buf[256];
    /* CcnetMessage *ccnet_message; */
    int len;

    if (log_level > ccnet_log_level)
        return;

    t = time(NULL);
    tm = localtime(&t);
    len = strftime (buf, 256, "[%x %X] ", tm);
    fputs (buf, logfp);
    fputs (message, logfp);
    fflush (logfp);

    /* Note, log module starts earlier than session, only 
     * send syslog when session exists */
    if (log_level <= G_LOG_LEVEL_MESSAGE && session) {
        int n = strlen (message);
        int max = 256 - len - 1;
        if (n > max) n = max;
        memcpy (buf + len, message, n);
        buf[len + n] = '\0';
    }

    /*
    if (log_level < G_LOG_LEVEL_MESSAGE) {
        g_on_error_stack_trace (NULL);
    }
    */
}

static int
get_debug_level(const char *str, int default_level)
{
    if (strcmp(str, "debug") == 0)
        return G_LOG_LEVEL_DEBUG;
    if (strcmp(str, "info") == 0)
        return G_LOG_LEVEL_INFO;
    if (strcmp(str, "warning") == 0)
        return G_LOG_LEVEL_WARNING;
    return default_level;
}

int
ccnet_log_init (const char *_logfile, const char *debug_level_str)
{
    g_log_set_handler (NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
                       | G_LOG_FLAG_RECURSION, ccnet_log, NULL);

    /* write all warnings from lib/ into ccnet.log */
    g_log_set_handler ("Ccnet", G_LOG_LEVEL_WARNING, ccnet_log, NULL);

    /* record all log message */
    ccnet_log_level = get_debug_level(debug_level_str, G_LOG_LEVEL_INFO);

    if (strcmp(_logfile, "-") == 0) {
        logfp = stdout;
        logfile = g_strdup (_logfile);
    }
    else {
        logfile = ccnet_expand_path (_logfile);

        if ((logfp = g_fopen (logfile, "a+")) == NULL) {
            ccnet_message ("Failed to open file %s\n", logfile);
            return -1;
        }
    }

    return 0;
}

int
ccnet_log_reopen ()
{
    FILE *fp, *oldfp;

    if (strcmp(logfile, "-") == 0)
        return 0;

    if ((fp = g_fopen (logfile, "a+")) == NULL) {
        ccnet_message ("Failed to open file %s\n", logfile);
        return -1;
    }

    //TODO: check file's health

    oldfp = logfp;
    logfp = fp;
    if (fclose(oldfp) < 0) {
        ccnet_message ("Failed to close file %s\n", logfile);
        return -1;
    }

    return 0;
}

static CcnetDebugFlags debug_flags = 0;

static GDebugKey debug_keys[] = {
  { "Peer", CCNET_DEBUG_PEER },
  { "Processor", CCNET_DEBUG_PROCESSOR },
  { "Netio", CCNET_DEBUG_NETIO },
  { "Message", CCNET_DEBUG_MESSAGE },
  { "Connection", CCNET_DEBUG_CONNECTION },
  { "Other", CCNET_DEBUG_OTHER },
};

gboolean
ccnet_debug_flag_is_set (CcnetDebugFlags flag)
{
    return (debug_flags & flag) != 0;
}

void
ccnet_debug_set_flags (CcnetDebugFlags flags)
{
    ccnet_message ("Set debug flags %#x\n", flags);
    debug_flags |= flags;
}

void
ccnet_debug_set_flags_string (const gchar *flags_string)
{
    guint nkeys = G_N_ELEMENTS (debug_keys);

    if (flags_string)
        ccnet_debug_set_flags (
            g_parse_debug_string (flags_string, debug_keys, nkeys));
}

void
ccnet_debug_impl (CcnetDebugFlags flag, const gchar *format, ...)
{
    if (flag & debug_flags) {
        va_list args;
        va_start (args, format);
        g_logv (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, format, args);
        va_end (args);
    }
}
