#ifndef CCNET_PROC_FACTORY_H
#define CCNET_PROC_FACTORY_H


#include <glib-object.h>

#include "processor.h"
#include "ccnet-object.h"

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
    struct CcnetSession  *session;

    int                   procs_alive_cnt; /*number of processors alive*/

    GList                *procs;   /* TODO: need to recyle the space
                                    * when it grows verylarge  */

    /* do keepalive if not receiving packet in `no_packet_timeout`,
     * default is 30 seconds */
    int                   no_packet_timeout;
};

struct _CcnetProcFactoryClass
{
    GObjectClass    parent_class;
};

GType ccnet_proc_factory_get_type (void);

CcnetProcFactory *ccnet_proc_factory_new (CcnetSession *session);
void ccnet_proc_factory_start (CcnetProcFactory *factory);

void ccnet_proc_factory_register_processor (CcnetProcFactory *facotry,
                                            const char *serv_name, 
                                            GType proc_type);

void ccnet_proc_factory_recycle(CcnetProcFactory *factory,
                                CcnetProcessor *processor);

void ccnet_proc_factory_shutdown_processors (
    CcnetProcFactory *factory, CcnetPeer *peer);


CcnetProcessor *ccnet_proc_factory_create_master_processor (
    CcnetProcFactory *factory, const char *serv_name, CcnetPeer *peer);

CcnetProcessor *ccnet_proc_factory_create_slave_processor (
    CcnetProcFactory *factory, const char *serv_name,
    CcnetPeer *peer, int req_id);

void ccnet_proc_factory_set_keepalive_timeout (CcnetProcFactory *factory,
                                               int timeout);

#endif
