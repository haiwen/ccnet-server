
AM_CPPFLAGS = @GLIB2_CFLAGS@ @GOBJECT_CFLAGS@ \
	-DCCNET_SERVER \
	-I$(top_srcdir)/net/common \
	-I$(top_srcdir)/include -I$(top_srcdir)/include/ccnet \
	-I$(top_srcdir)/lib \
	-I$(top_builddir)/include \
	-I$(top_builddir)/lib \
	@SEARPC_CFLAGS@ \
	@MYSQL_CFLAGS@ \
	@PGSQL_CFLAGS@ \
	-Wall

bin_PROGRAMS = ccnet-server

noinst_HEADERS = server-session.h user-mgr.h group-mgr.h org-mgr.h


common_srcs = ../common/ccnet-db.c \
	../common/session.c ../common/peer-mgr.c ../common/packet-io.c \
	../common/message.c ../common/perm-mgr.c \
	../common/log.c ../common/peer.c ../common/algorithms.c \
	../common/handshake.c ../common/processor.c \
	../common/getgateway.c ../common/connect-mgr.c \
	../common/message-manager.c \
	../common/proc-factory.c \
	../common/ccnet-config.c \
	../common/rpc-service.c \
	../common/peermgr-message.c \
	../common/processors/sendmsg-proc.c ../common/processors/rcvmsg-proc.c \
	../common/processors/rcvcmd-proc.c \
	../common/processors/putpubinfo-proc.c \
	../common/processors/getpubinfo-proc.c \
	../common/processors/keepalive2-proc.c \
	../common/processors/mqserver-proc.c \
	../common/processors/service-proxy-proc.c \
	../common/processors/service-stub-proc.c \
	../common/processors/rpcserver-proc.c \
	../common/processors/threaded-rpcserver-proc.c \
	../common/processors/echo-proc.c \
	../common/processors/sendsessionkey-proc.c \
	../common/processors/recvsessionkey-proc.c \
	../common/processors/sendsessionkey-v2-proc.c \
	../common/processors/recvsessionkey-v2-proc.c

ccnet_server_SOURCES = ccnet-server.c \
	server-session.c user-mgr.c group-mgr.c org-mgr.c \
	$(common_srcs)

ccnet_server_LDADD = @LIBEVENT_LIBS@ $(top_builddir)/lib/libccnetd.la \
           @GLIB2_LIBS@ @GOBJECT_LIBS@ @SSL_LIBS@ @LIB_RT@ @LIB_UUID@ -lsqlite3 \
           -lpthread \
           @LIB_WS32@ @LIB_INTL@ @LIB_IPHLPAPI@ @SEARPC_LIBS@ \
           @LDAP_LIBS@ @MYSQL_LIBS@ -lsqlite3 @PGSQL_LIBS@


ccnet_server_LDFLAGS = @CONSOLE@ -no-undefined
