#ifndef _RQUOTA_H_RPCGEN
#define _RQUOTA_H_RPCGEN

#include <rpc/rpc.h>

#define RQ_PATHLEN 1024

struct getquota_args
{
  char *gqa_pathp;
  int gqa_uid;
};
typedef struct getquota_args getquota_args;

struct ext_getquota_args
{
  char *gqa_pathp;
  int gqa_type;
  int gqa_id;
};
typedef struct ext_getquota_args ext_getquota_args;

struct rquota
{
  int rq_bsize;
  bool_t rq_active;
  u_int rq_bhardlimit;
  u_int rq_bsoftlimit;
  u_int rq_curblocks;
  u_int rq_fhardlimit;
  u_int rq_fsoftlimit;
  u_int rq_curfiles;
  u_int rq_btimeleft;
  u_int rq_ftimeleft;
};
typedef struct rquota rquota;

enum gqr_status
{
  Q_OK = 1,
  Q_NOQUOTA = 2,
  Q_EPERM = 3
};
typedef enum gqr_status gqr_status;

struct getquota_rslt
{
  gqr_status status;
  union
  {
    rquota gqr_rquota;
  } getquota_rslt_u;
};
typedef struct getquota_rslt getquota_rslt;

#define RQUOTAPROG ((unsigned long)(100011))
#define RQUOTAVERS ((unsigned long)(1))

#define RQUOTAPROC_GETQUOTA ((unsigned long)(1))
extern getquota_rslt *rquotaproc_getquota_1 (getquota_args *, CLIENT *);
extern getquota_rslt *rquotaproc_getquota_1_svc (getquota_args *,
                                                 struct svc_req *);
#define RQUOTAPROC_GETACTIVEQUOTA ((unsigned long)(2))
extern getquota_rslt *rquotaproc_getactivequota_1 (getquota_args *, CLIENT *);
extern getquota_rslt *rquotaproc_getactivequota_1_svc (getquota_args *,
                                                       struct svc_req *);
extern int rquotaprog_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

/* the xdr functions */

extern bool_t xdr_getquota_args (XDR *, getquota_args *);
extern bool_t xdr_rquota (XDR *, rquota *);
extern bool_t xdr_gqr_status (XDR *, gqr_status *);
extern bool_t xdr_getquota_rslt (XDR *, getquota_rslt *);

#define EXT_RQUOTAVERS ((unsigned long)(2))
extern bool_t xdr_ext_getquota_args (XDR *, ext_getquota_args *);

#endif /* !_RQUOTA_H_RPCGEN */
