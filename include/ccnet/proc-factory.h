/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_PROC_FACTORY_H
#define CCNET_PROC_FACTORY_H


#include <glib-object.h>

#include "processor.h"


#define CCNET_TYPE_PROC_FACTORY                  (ccnet_proc_factory_get_type ())
#define CCNET_PROC_FACTORY(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_PROC_FACTORY, CcnetProcFactory))
#define CCNET_IS_PROC_FACTORY(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_PROC_FACTORY))
#define CCNET_PROC_FACTORY_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_PROC_FACTORY, CcnetProcFactoryClass))
#define CCNET_IS_PROC_FACTORY_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_PROC_FACTORY))
#define CCNET_PROC_FACTORY_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_PROC_FACTORY, CcnetProcFactoryClass))

typedef struct _CcnetProcFactory CcnetProcFactory;
typedef struct _CcnetProcFactoryClass CcnetProcFactoryClass;

struct _CcnetProcFactory
{
    GObject         parent_instance;

    /* protected */
    CcnetClient   *session;
};

struct _CcnetProcFactoryClass
{
    GObjectClass    parent_class;
};

GType ccnet_proc_factory_get_type (void);

CcnetProcFactory *ccnet_proc_factory_new (CcnetClient *session);

void ccnet_proc_factory_register_processor (CcnetProcFactory *facotry,
					    const char *serv_name, 
					    GType proc_type);


enum {
    SLAVE  = 0,
    MASTER = 1,
};


CcnetProcessor*
ccnet_proc_factory_create_processor (CcnetProcFactory *factory,
                                     const char *serv_name,
                                     int is_master,
                                     int req_id);

CcnetProcessor*
ccnet_proc_factory_create_master_processor (CcnetProcFactory *factory,
                                            const char *serv_name);

CcnetProcessor *
ccnet_proc_factory_create_remote_master_processor (CcnetProcFactory *factory,
                                                   const char *serv_name,
                                                   const char *peer_id);
CcnetProcessor *
ccnet_proc_factory_create_slave_processor (CcnetProcFactory *factory,
                                           const char *serv_name,
                                           const char *peer_id,
                                           int req_id);

void ccnet_proc_factory_recycle(CcnetProcFactory *factory,
                                CcnetProcessor *processor);


#endif
