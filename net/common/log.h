/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_LOG_H
#define CCNET_LOG_H

#ifndef ccnet_warning
#define ccnet_warning(fmt, ...) g_warning("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#ifndef ccnet_error
#define ccnet_error(fmt, ...)   g_error("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#ifndef ccnet_message
#define ccnet_message(fmt, ...) g_message("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

int ccnet_log_init (const char *logfile, const char *log_level_str);
int ccnet_log_reopen ();

typedef enum
{
    CCNET_DEBUG_PEER = 1 << 1,
    CCNET_DEBUG_PROCESSOR = 1 << 2,
    CCNET_DEBUG_NETIO = 1 << 3,
    CCNET_DEBUG_CONNECTION = 1 << 4,
    CCNET_DEBUG_MESSAGE = 1 << 5,
    CCNET_DEBUG_OTHER = 1 << 6,
} CcnetDebugFlags;
 
gboolean ccnet_debug_flag_is_set (CcnetDebugFlags flag);
void ccnet_debug_set_flags (CcnetDebugFlags flag);
void ccnet_debug_set_flags_string (const gchar *flags_string);

void ccnet_debug_impl (CcnetDebugFlags flag, const gchar *format, ...);

#define ccnet_debug(format, ...)


#endif  /* CCNET_LOG_H */

#undef ccnet_debug
#define ccnet_debug(format, ...)

#ifdef DEBUG_FLAG

#undef ccnet_debug
#define ccnet_debug(fmt, ...)  \
    ccnet_debug_impl (DEBUG_FLAG, "%.15s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#endif  /* DEBUG_FLAG */


