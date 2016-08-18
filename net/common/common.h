/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef COMMON_H
#define COMMON_H

#ifdef HAVE_CONFIG_H
 #include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>             /* uint32_t */
#include <sys/types.h>          /* size_t */
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "option.h"

#ifndef ULLONG_MAX
  #define ULLONG_MAX	18446744073709551615ULL
#endif

#define IPEERMGR_APP        "IPeerMgr"

#include <glib.h>

#include "utils.h"
#include <ccnet/valid-check.h>

#endif
