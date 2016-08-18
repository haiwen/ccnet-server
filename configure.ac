dnl Process this file with autoconf to produce a configure script.


AC_PREREQ(2.61)
AC_INIT([ccnet], [5.1.4], [daniel.pan@seafile.com])
AC_CONFIG_SRCDIR([net/server/ccnet-server.c])
AC_CONFIG_HEADER([config.h])

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.9 foreign])

#AC_MINGW32
AC_CANONICAL_BUILD

dnl enable the build of share library by default
AC_ENABLE_SHARED

AC_SUBST(LIBTOOL_DEPS)

# Checks for programs.
AC_PROG_CC
#AM_C_PROTOTYPES
AC_C_CONST
AC_PROG_MAKE_SET
# AC_PROG_RANLIB
LT_INIT

# Checks for headers.
AC_CHECK_HEADERS([sys/ioctl.h sys/time.h stdarg.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_SYS_LARGEFILE

# Checks for library functions.
#AC_CHECK_FUNCS([alarm dup2 ftruncate getcwd gethostbyname gettimeofday memmove memset mkdir rmdir select setlocale socket strcasecmp strchr strdup strrchr strstr strtol uname utime strtok_r sendfile])

# check platform
AC_MSG_CHECKING(for WIN32)
if test "$build_os" = "mingw32" -o "$build_os" = "mingw64"; then
  bwin32=true
  AC_MSG_RESULT(compile in mingw)
else
  AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(for Mac)
if test "$(uname)" = "Darwin"; then
  bmac=true
  AC_MSG_RESULT(compile in mac)
else
  AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(for Linux)
if test "$bmac" != "true" -a "$bwin32" != "true"; then
  blinux=true
  AC_MSG_RESULT(compile in linux)
else
  AC_MSG_RESULT(no)
fi

AC_ARG_ENABLE(ldap, AC_HELP_STRING([--enable-ldap], [enable LDAP]),
   [compile_ldap=$enableval],[compile_ldap="no"])

AC_ARG_ENABLE(python,
              AC_HELP_STRING([--enable-python],[build ccnet python binding]),
              [compile_python=$enableval],
              [compile_python=yes])

AM_CONDITIONAL([COMPILE_PYTHON], [test "${compile_python}" = "yes"])

AM_CONDITIONAL([WIN32], [test "$bwin32" = "true"])
AM_CONDITIONAL([MACOS], [test "$bmac" = "true"])
AM_CONDITIONAL([LINUX], [test "$blinux" = "true"])


# check libraries
if test "$bwin32" != true; then
  if test "$bmac" = true; then
  AC_CHECK_LIB(c, uuid_generate, [echo "found library uuid"],
          AC_MSG_ERROR([*** Unable to find uuid_generate in libc]), )
  else
  AC_CHECK_LIB(uuid, uuid_generate, [echo "found library uuid"],
          AC_MSG_ERROR([*** Unable to find uuid library]), )
  fi
fi

AC_CHECK_LIB(pthread, pthread_create, [echo "found library pthread"], AC_MSG_ERROR([*** Unable to find pthread library]), )
AC_CHECK_LIB(sqlite3, sqlite3_open,[echo "found library sqlite3"] , AC_MSG_ERROR([*** Unable to find sqlite3 library]), )
AC_CHECK_LIB(crypto, SHA1_Init, [echo "found library crypto"], AC_MSG_ERROR([*** Unable to find openssl crypto library]), )

PTHREAD_CFLAGS=-pthread
PTHREAD_LIBS=-lpthread
has_winpthread=false
if test "$bwin32" = "true"; then
  has_winpthread=false
  dnl this will tell us if the implementation of pthread is winpthread
  AC_CHECK_LIB(winpthread, pthread_create, has_winpthread=true,
               [echo "found library winpthread"], )
  PTHREAD_CFLAGS=-pthread
  PTHREAD_LIBS=-lwinpthread
fi

dnl Saddly, the old mingw gcc doesn't support -pthread flag
if test "$bwin32" = "true" -a "$has_winpthread" != "true"; then
  PTHREAD_CFLAGS=
  PTHREAD_LIBS=-lpthread
fi

AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_LIBS)

dnl Do we need to use AX_LIB_SQLITE3 to check sqlite?
dnl AX_LIB_SQLITE3

CONSOLE=
if test "$bwin32" = "true"; then
  AC_ARG_ENABLE(console, AC_HELP_STRING([--enable-console], [enable console]),
      [console=$enableval],[console="yes"])
  if test x${console} != xyes ; then
    CONSOLE="-Wl,--subsystem,windows -Wl,--entry,_mainCRTStartup"
  fi
fi
AC_SUBST(CONSOLE)

if test "$bwin32" = true; then
  LIB_WS32=-lws2_32
  LIB_GDI32=-lgdi32
  LIB_RT=
  LIB_INTL=-lintl
  LIBS=
  LIB_RESOLV=
  LIB_UUID=-lrpcrt4
  LIB_IPHLPAPI=-liphlpapi
  LIB_SHELL32=-lshell32
  LIB_PSAPI=-lpsapi
  MSVC_CFLAGS=-D__MSVCRT_VERSION__=0x0601
  LIB_DIRWATCH=
elif test "$bmac" = true ; then
  LIB_WS32=
  LIB_GDI32=
  LIB_RT=
  LIB_INTL=
  LIB_RESOLV=-lresolv
  LIB_UUID=
  LIB_IPHLPAPI=
  LIB_SHELL32=
  LIB_PSAPI=
  MSVC_CFLAGS=
  LIB_DIRWATCH="-framework CoreServices"
else
  LIB_WS32=
  LIB_GDI32=
  LIB_RT=
  LIB_INTL=
  LIB_RESOLV=-lresolv
  LIB_UUID=-luuid
  LIB_IPHLPAPI=
  LIB_SHELL32=
  LIB_PSAPI=
  MSVC_CFLAGS=
  LIB_DIRWATCH=
fi

AC_SUBST(LIB_WS32)
AC_SUBST(LIB_GDI32)
AC_SUBST(LIB_RT)
AC_SUBST(LIB_INTL)
AC_SUBST(LIB_RESOLV)
AC_SUBST(LIB_UUID)
AC_SUBST(LIB_IPHLPAPI)
AC_SUBST(LIB_SHELL32)
AC_SUBST(LIB_PSAPI)
AC_SUBST(MSVC_CFLAGS)
AC_SUBST(LIB_DIRWATCH)

LIBEVENT_REQUIRED=2.0
# gtk and glib
APPINDICATOR_REQUIRED=0.0.7
GLIB_REQUIRED=2.16.0
GTK_REQUIRED=2.16.0
SEARPC_REQUIRED=1.0
ZDB_REQUIRED=2.10
LIBNAUTILUS_EXTENSION_REQUIRED=2.30.1
SEARPC_REQUIRED=1.0
CURL_REQUIRED=7.17

PKG_CHECK_MODULES(SSL, [openssl])
AC_SUBST(SSL_CFLAGS)
AC_SUBST(SSL_LIBS)

PKG_CHECK_MODULES(GLIB2, [glib-2.0 >= $GLIB_REQUIRED])
AC_SUBST(GLIB2_CFLAGS)
AC_SUBST(GLIB2_LIBS)

PKG_CHECK_MODULES(GOBJECT, [gobject-2.0 >= $GLIB_REQUIRED])
AC_SUBST(GOBJECT_CFLAGS)
AC_SUBST(GOBJECT_LIBS)

PKG_CHECK_MODULES(SEARPC, [libsearpc >= $SEARPC_REQUIRED])
AC_SUBST(SEARPC_CFLAGS)
AC_SUBST(SEARPC_LIBS)

PKG_CHECK_MODULES(LIBEVENT, [libevent >= $LIBEVENT_REQUIRED])
AC_SUBST(LIBEVENT_CFLAGS)
AC_SUBST(LIBEVENT_LIBS)

if test x${compile_python} = xyes; then
   AM_PATH_PYTHON([2.6])

   if test "$bwin32" = true; then
       # set pyexecdir to somewhere like /c/Python26/Lib/site-packages
       pyexecdir=${PYTHON_DIR}/Lib/site-packages
       pythondir=${pyexecdir}
       pkgpyexecdir=${pyexecdir}/${PACKAGE}
       pkgpythondir=${pythondir}/${PACKAGE}

   fi # end for bwin32

fi

mysql="yes"
check_mysql_config() 
{
        AC_PATH_PROG([MYSQLCONFIG], [mysql_config], [no], [$PATH:/usr/local/bin:/usr/local/mysql/bin])
        if test "x$MYSQLCONFIG" = "xno" 
        then
                AC_MSG_WARN([mysql_config is required to build seafile server with mysql])
                mysql="no"
        fi
}
AC_MSG_CHECKING(for mysql)
AC_ARG_WITH([mysql], 
        AS_HELP_STRING([--with-mysql(=<path>)], 
                [Path is optional and if given should specify the full path to the MySQL
                 configure script, mysql_config. E.g. --with-mysql=/<path>/mysql_config]), 
        [
                if test "xno" = "x$with_mysql"; then
                        AC_MSG_RESULT([no])
                        mysql="no"
                else
                        AC_MSG_RESULT([yes])
                        AC_CHECK_FILE([$with_mysql], [MYSQLCONFIG=$with_mysql], [check_mysql_config])        
                fi
        ],
        [
                AC_MSG_RESULT([yes])
                check_mysql_config
        ])
if test "xyes" = "x$mysql"; then
        tmp_CPPFLAGS=$CPPFLAGS
        tmp_LDFLAGS=$LDFLAGS
        CPPFLAGS="`$MYSQLCONFIG --include` $CPPFLAGS"
        LDFLAGS="`$MYSQLCONFIG --libs` $LDFLAGS"
        AC_CHECK_HEADERS([mysql.h])
        if test "xyes" = "x$mysql"; then
	        echo "found mysql client library"
		MYSQL_CFLAGS=`$MYSQLCONFIG --include`
                MYSQL_LIBS=`$MYSQLCONFIG --libs`		
		AC_SUBST(MYSQL_CFLAGS)
		AC_SUBST(MYSQL_LIBS)
        fi
        CPPFLAGS=$tmp_CPPFLAGS
        LDFLAGS=$tmp_LDFLAGS
fi

postgresql="yes"
check_postgres_config() 
{
        AC_PATH_PROG([PGCONFIG], [pg_config], [no], [$PATH:/usr/local/bin:/usr/local/pgsql/bin])
        if test "x$PGCONFIG" = "xno"
        then
                AC_MSG_WARN([pg_config is required to build seafile server with postgresql])
                postgresql="no"
        fi
}
AC_MSG_CHECKING(for postgresql)
AC_ARG_WITH([postgresql], 
        AS_HELP_STRING([--with-postgresql(=<path>)], 
                [Path is optional and if given should specify the full path to the PostgreSQL
                 configure script, pg_config. E.g. --with-postgresql=/<path>/pg_config]), 
        [
                if test "xno" = "x$with_postgresql"; then
                        AC_MSG_RESULT([no])
                        postgresql="no"
                else
                        AC_MSG_RESULT([yes])
                        AC_CHECK_FILE([$with_postgresql], [PGCONFIG=$with_postgresql],[check_postgres_config])
                fi
        ],
        [
                AC_MSG_RESULT([yes])
                check_postgres_config
        ])
if test "xyes" = "x$postgresql"; then
        tmp_CPPFLAGS=$CPPFLAGS
        tmp_LDFLAGS=$LDFLAGS
        CPPFLAGS="-I`$PGCONFIG --includedir` $CPPFLAGS"
        LDFLAGS="-L`$PGCONFIG --libdir` $LDFLAGS"
        AC_CHECK_HEADERS([libpq-fe.h], [], [postgresql="no"])
        if test "xyes" = "x$postgresql"; then
                echo "found postgresql client library"
                PGSQL_CFLAGS="-I`$PGCONFIG --includedir`"
                PGSQL_LIBS="-L`$PGCONFIG --libdir` -lpq"
		AC_SUBST(PGSQL_CFLAGS)
		AC_SUBST(PGSQL_LIBS)
        fi
        CPPFLAGS=$tmp_CPPFLAGS
        LDFLAGS=$tmp_LDFLAGS
fi

if test "${compile_ldap}" = "yes"; then
   if test "$bwin32" != true; then
      AC_CHECK_LIB(ldap, ldap_init, [have_ldap="yes"],
         AC_MSG_ERROR([*** Unable to find ldap client library]), )

      if test "${have_ldap}" = "yes"; then
         echo "found ldap client library"
         AC_DEFINE([HAVE_LDAP], [1], [Define if ldap library exists.])
         AC_SUBST(LDAP_LIBS, "-lldap -llber")
      fi
   else
      AC_DEFINE([HAVE_LDAP], [1], [Define if ldap library exists.])
      AC_SUBST(LDAP_LIBS, "-lWldap32")
   fi


fi

ac_configure_args="$ac_configure_args -q"

AC_CONFIG_FILES(
	Makefile
    libccnet.pc
    net/Makefile
    net/server/Makefile
    net/common/Makefile
    net/common/db-wrapper/Makefile
    lib/Makefile
    tools/Makefile
    include/Makefile
    include/ccnet/Makefile
    python/Makefile
    python/ccnet/Makefile
)

AC_OUTPUT
