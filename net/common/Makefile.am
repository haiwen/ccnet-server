SUBDIRS = db-wrapper

PROC_HEADER_FILES = \
	$(addprefix processors/, \
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

common_headers = \
	algorithms.h \
	proc-factory.h session.h \
	common.h handshake.h perm-mgr.h \
	peer.h connect-mgr.h \
	packet-io.h ccnet-config.h \
	log.h peer-mgr.h \
	message.h \
	getgateway.h message-manager.h \
	processor.h \
	peermgr-message.h \
	rpc-service.h \
	ccnet-db.h

noinst_HEADERS = $(common_headers) $(PROC_HEADER_FILES)
