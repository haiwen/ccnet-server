/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef VALID_CHECK_H
#define VALID_CHECK_H

#include <string.h>

inline static gboolean user_id_valid(const char *id)
{
    if (!id || strlen(id) != 40)
        return FALSE;
    return TRUE;
}

inline static gboolean peer_id_valid(const char *id)
{
    if (!id || strlen(id) != 40)
        return FALSE;
    return TRUE;
}

gboolean is_uuid_valid (const char *uuid_str);

inline static gboolean group_id_valid(const char *id)
{
    return is_uuid_valid(id);
}

#endif
