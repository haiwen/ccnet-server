
AM_CPPFLAGS = @GLIB2_CFLAGS@ @GOBJECT_CFLAGS@ \
	-DCCNET_SERVER \
	-I$(top_srcdir)/net/common \
	-I$(top_srcdir)/include -I$(top_srcdir)/include/ccnet \
	-I$(top_srcdir)/lib \
	-I$(top_builddir)/include \
	-I$(top_builddir)/lib \
	@SEARPC_CFLAGS@ \
	-Wall

bin_PROGRAMS = ccnet-server

PROC_HEADER_FILES = \
	$(addprefix ../common/processors/, \
	rcvmsg-proc.h \
	rcvcmd-proc.h \
	sendmsg-proc.h \
	getpubinfo-proc.h putpubinfo-proc.h \
	keepalive2-proc.h \
	mqserver-proc.h \
	service-proxy-proc.h service-stub-proc.h \
	rpcserver-proc.h \
	threaded-rpcserver-proc.h \
	echo-proc.h \
	sendsessionkey-proc.h \
	recvsessionkey-proc.h \
	sendsessionkey-v2-proc.h \
	recvsessionkey-v2-proc.h )

common_headers = 
	../common/algorithms.h \
	../common/proc-factory.h ../common/session.h \
	../common/common.h ../common/handshake.h ../common/perm-mgr.h \
	../common/peer.h ../common/connect-mgr.h \
	../common/packet-io.h ../common/ccnet-config.h \
	../common/log.h ../common/peer-mgr.h \
	../common/message.h \
	../common/getgateway.h ../common/message-manager.h \
	../common/processor.h \
	../common/peermgr-message.h \
	../common/rpc-service.h \
	../common/ccnet-db.h


noinst_HEADERS = $(common_headers) \
	server-session.h user-mgr.h group-mgr.h org-mgr.h \
	$(PROC_HEADER_FILES)


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
           $(top_builddir)/net/common/db-wrapper/libdbwrapper.la \
           @GLIB2_LIBS@ @GOBJECT_LIBS@ @SSL_LIBS@ @LIB_RT@ @LIB_UUID@ -lsqlite3 \
           -lpthread \
           @LIB_WS32@ @LIB_INTL@ @LIB_IPHLPAPI@ @SEARPC_LIBS@ \
           @LDAP_LIBS@ @MYSQL_LIBS@ @PGSQL_LIBS@


ccnet_server_LDFLAGS = @CONSOLE@ -no-undefined
