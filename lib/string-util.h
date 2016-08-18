/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_STRING_H
#define CCNET_STRING_H

#include <stdio.h>

#define END_0(buf,len) (buf[(len)-1] == '\0')


static inline int get_version(char *str)
{
    int v;

    if (str[0] != 'v')
        return 0;
    if (sscanf(str+1, "%d", &v) != 1)
        return 0;
    return v;
}



#define sgoto_next(p) do {      \
        while (*p != ' ' && *p) ++p;            \
        if (*p != ' ')                          \
            goto error;                         \
        *p = '\0';                              \
        ++p;                                    \
    } while (0)

#define sget_len(val, p) do { \
        char *tmp = p;        \
        sgoto_next(p);        \
        val = atoi(tmp);        \
        if (val == 0)         \
            goto error;       \
    } while (0)


/* get a string with format "%s " */
#define sget_str(str, p) do { \
        str = p;              \
        sgoto_next(p);        \
    } while (0)

/* get a string with format "%d %s " */
#define sget_str_with_len(str, p) do { \
        int len;                       \
        sget_len(len, p);              \
        str = p;                       \
        p += len;                      \
        *p = '\0';                     \
        ++p;                           \
    } while (0)



#endif
