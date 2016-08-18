/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_PROCESSOR_H
#define CCNET_PROCESSOR_H

#include <glib.h>
#include <glib-object.h>
#include <stdint.h>
#include <ccnet/status-code.h>

#include <pthread.h>

#ifdef WIN32
#define ccnet_pipe_t intptr_t
#else
#define ccnet_pipe_t int
#endif

struct _CcnetClient;

#define CCNET_TYPE_PROCESSOR                  (ccnet_processor_get_type ())
#define CCNET_PROCESSOR(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_PROCESSOR, CcnetProcessor))
#define CCNET_IS_PROCESSOR(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_PROCESSOR))
#define CCNET_PROCESSOR_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_PROCESSOR, CcnetProcessorClass))
#define CCNET_IS_PROCESSOR_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_PROCESSOR))
#define CCNET_PROCESSOR_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_PROCESSOR, CcnetProcessorClass))

typedef struct _CcnetProcessor CcnetProcessor;
typedef struct _CcnetProcessorClass CcnetProcessorClass;


struct _CcnetProcessor {
    GObject         parent_instance;

    char                  *peer_id;
    struct _CcnetClient   *session;

    char                  *name;

    /* highest bit = 0, master; highest bit = 1, slave */
    uint32_t               id;
    int                    state;
    int                    failure;

    struct CcnetTimer     *timer;

    int                    num_retry;

    /* Set to 1 when handling update or response */
    gboolean               is_active;

    /* Internal flags for handling processor thread. */
    gboolean               thread_running;
    gboolean               delay_shutdown;
    gboolean               was_success;
};

enum {
    STATE_IN_SHUTDOWN = 1 << 8,
    STATE_RECYCLED,
};

enum {
    PROC_NOTSET,
    PROC_DONE,
    PROC_REMOTE_DEAD,
    PROC_NO_SERVICE,
    PROC_PERM_ERR,
    PROC_BAD_RESP,              /* code[0] =='5' || '4' */
};

#define SLAVE_MASK 0x80000000
#define REQUEST_ID_MASK 0x7fffffff
#define REQUEST_ID(processor_id) ((processor_id) & REQUEST_ID_MASK)
#define UPDATE_ID(processor_id) ((processor_id) & REQUEST_ID_MASK)
#define RESPONSE_ID(processor_id) ((processor_id) & REQUEST_ID_MASK)
#define SLAVE_ID(request_id) ((request_id) | SLAVE_MASK)
#define MASTER_ID(request_id) (request_id)

#define PRINT_ID(processor_id) ((processor_id) & SLAVE_MASK) ?  \
                   - REQUEST_ID(processor_id) : REQUEST_ID(processor_id)
#define IS_SLAVE(processor) ((processor)->id & SLAVE_MASK)
#define GET_PNAME(processor) CCNET_PROCESSOR_GET_CLASS(processor)->name

struct _CcnetProcessorClass {
    GObjectClass   parent_class;

    char          *name;

    /* pure virtual function */
    int       (*start)           (CcnetProcessor *processor, 
                                  int argc, char **argv);
    void      (*handle_update)   (CcnetProcessor *processor,
                                  char *code, char *code_msg,
                                  char *content, int clen);
    void      (*handle_response) (CcnetProcessor *processor, 
                                  char *code, char *code_msg,
                                  char *content, int clen);

    void      (*handle_sigchld)  (CcnetProcessor *processor,
                                  int status);

    void      (*shutdown)        (CcnetProcessor *processor);

    void      (*release_resource) (CcnetProcessor *processor);
};

GType ccnet_processor_get_type ();

int ccnet_processor_start (CcnetProcessor *processor, 
                            int argc, char **argv);

int ccnet_processor_startl 
                 (CcnetProcessor *processor, ...) G_GNUC_NULL_TERMINATED;

void ccnet_processor_done (CcnetProcessor *processor, gboolean success);

void ccnet_processor_handle_update (CcnetProcessor *processor, 
                                    char *code, char *code_msg,
                                    char *content, int clen);

void ccnet_processor_handle_response (CcnetProcessor *processor,
                                      char *code, char *code_msg,
                                      char *content, int clen);

void ccnet_processor_handle_sigchld (CcnetProcessor *processor,
                                     int status);


void ccnet_processor_send_request (CcnetProcessor *processor,
                                   const char *request);

void ccnet_processor_send_request_l (CcnetProcessor *processor, 
                                     ...) G_GNUC_NULL_TERMINATED;

void ccnet_processor_send_update(CcnetProcessor *processor, 
                                 const char *code,
                                 const char *code_msg,
                                 const char *content, int clen);

void ccnet_processor_send_response(CcnetProcessor *processor, 
                                   const char *code,
                                   const char *code_msg,
                                   const char *content, int clen);

/*
  The thread func should return the result back by
     return (void *)result;
  The result will be passed to ProcThreadDoneFunc.
  In the done func, the caller should check whether processor->delay_shutdown
  is TRUE. If it is, you should call processor_done().
 */
typedef void* (*ProcThreadFunc)(void *data);
typedef void (*ProcThreadDoneFunc)(void *result);

struct _CcnetJobManager;

/*
 * @job_mgr: the thread pool to create the worker thread.
 *           If it's NULL, processor->session->job_mgr will be used.
 */
int ccnet_processor_thread_create (CcnetProcessor *processor,
                                   struct _CcnetJobManager *job_mgr,
                                   ProcThreadFunc func,
                                   ProcThreadDoneFunc done_func,
                                   void *data);

#endif
