#include "Quota.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "myconfig.h"

#ifdef SFIO_VERSION
#include "stdio_wrap.h"
#else
#define std_fopen fopen
#define std_fclose fclose
#endif

#ifdef AFSQUOTA
#include "include/afsquota.h"
#endif

#ifdef SOLARIS_VXFS
#include "include/vxquotactl.h"
#endif

#ifndef AIX
#ifndef NO_MNTENT
FILE *mtab = NULL;
#else /* NO_MNTENT */
#ifdef USE_STATVFS_MNTINFO
struct statvfs *mntp, *mtab = NULL;
#else
struct statfs *mntp, *mtab = NULL;
#endif
int mtab_size = 0;
#endif /* NO_MNTENT */
#else  /* AIX */
static struct vmount *mtab = NULL;
static aix_mtab_idx, aix_mtab_count;
#endif

#ifndef NO_RPC
static struct
{
  char use_tcp;
  unsigned short port;
  unsigned timeout;
} quota_rpc_cfg = { FALSE, 0, 4000 };

static struct
{
  int uid;
  int gid;
  char hostname[MAX_MACHINE_NAME + 1];
} quota_rpc_auth = { -1, -1, { 0 } };

static const char *quota_rpc_strerror = NULL;

struct quota_xs_nfs_rslt
{
  double bhard;
  double bsoft;
  double bcur;
  time_t btime;
  double fhard;
  double fsoft;
  double fcur;
  time_t ftime;
};

/*
 * fetch quotas from remote host
 */

int
callaurpc (char *host, int prognum, int versnum, int procnum, xdrproc_t inproc,
           char *in, xdrproc_t outproc, char *out)
{
  struct sockaddr_in remaddr;
  struct hostent *hp;
  enum clnt_stat clnt_stat;
  struct timeval rep_time, timeout;
  CLIENT *client;
  int socket = RPC_ANYSOCK;

  /*
   *  Get IP address; by default the port is determined via remote
   *  portmap daemon; different ports and protocols can be configured
   */
  hp = gethostbyname (host);
  if (hp == NULL)
    {
      quota_rpc_strerror = clnt_sperrno (RPC_UNKNOWNHOST);
      return -1;
    }

  rep_time.tv_sec = quota_rpc_cfg.timeout / 1000;
  rep_time.tv_usec = (quota_rpc_cfg.timeout % 1000) * 1000;
  memcpy ((char *)&remaddr.sin_addr, (char *)hp->h_addr, hp->h_length);
  remaddr.sin_family = AF_INET;
  remaddr.sin_port = htons (quota_rpc_cfg.port);

  /*
   *  Create client RPC handle
   */
  client = NULL;
  if (!quota_rpc_cfg.use_tcp)
    {
      client = (CLIENT *)clntudp_create (&remaddr, prognum, versnum, rep_time,
                                         &socket);
    }
  else
    {
      client = (CLIENT *)clnttcp_create (&remaddr, prognum, versnum, &socket,
                                         0, 0);
    }

  if (client == NULL)
    {
      if (rpc_createerr.cf_stat != RPC_SUCCESS)
        quota_rpc_strerror = clnt_sperrno (rpc_createerr.cf_stat);
      else /* should never happen (may be due to inconsistent symbol resolution
            */
        quota_rpc_strerror = "RPC creation failed for unknown reasons";
      return -1;
    }

  /*
   *  Create an authentication handle
   */
  if ((quota_rpc_auth.uid != -1) && (quota_rpc_auth.gid != -1))
    {
      client->cl_auth
          = authunix_create (quota_rpc_auth.hostname, quota_rpc_auth.uid,
                             quota_rpc_auth.gid, 0, 0);
    }
  else
    {
      client->cl_auth = authunix_create_default ();
    }

  /*
   *  Call remote server
   */
  timeout.tv_sec = quota_rpc_cfg.timeout / 1000;
  timeout.tv_usec = (quota_rpc_cfg.timeout % 1000) * 1000;
  clnt_stat = clnt_call (client, procnum, inproc, in, outproc, out, timeout);

  if (client->cl_auth)
    {
      auth_destroy (client->cl_auth);
      client->cl_auth = NULL;
    }
  clnt_destroy (client);

  if (clnt_stat != RPC_SUCCESS)
    {
      quota_rpc_strerror = clnt_sperrno (clnt_stat);
      return -1;
    }
  else
    return 0;
}

int
getnfsquota (char *hostp, char *fsnamep, int uid, int kind,
             struct quota_xs_nfs_rslt *rslt)
{
  struct getquota_args gq_args;
  struct getquota_rslt gq_rslt;
#ifdef USE_EXT_RQUOTA
  ext_getquota_args ext_gq_args;

  /*
   * First try USE_EXT_RQUOTAPROG (Extended quota RPC)
   */
  ext_gq_args.gqa_pathp = fsnamep;
  ext_gq_args.gqa_type = ((kind != 0) ? GQA_TYPE_GRP : GQA_TYPE_USR);
  ext_gq_args.gqa_id = uid;

  if (callaurpc (hostp, RQUOTAPROG, EXT_RQUOTAVERS, RQUOTAPROC_GETQUOTA,
                 (xdrproc_t)xdr_ext_getquota_args, (char *)&ext_gq_args,
                 (xdrproc_t)xdr_getquota_rslt, (char *)&gq_rslt)
      != 0)
#endif
    {
      if (kind == 0)
        {
          /*
           * Fall back to RQUOTAPROG if the server (or client via compile
           * switch) doesn't support extended quota RPC (i.e. only supports
           * user quota)
           */
          gq_args.gqa_pathp = fsnamep;
          gq_args.gqa_uid = uid;

          if (callaurpc (hostp, RQUOTAPROG, RQUOTAVERS, RQUOTAPROC_GETQUOTA,
                         (xdrproc_t)xdr_getquota_args, (char *)&gq_args,
                         (xdrproc_t)xdr_getquota_rslt, (char *)&gq_rslt)
              != 0)
            {
              return -1;
            }
        }
      else
        {
#ifndef USE_EXT_RQUOTA
          quota_rpc_strerror = "RPC: group quota not supported by RPC";
          errno = ENOTSUP;
#endif
          return -1;
        }
    }

  switch (gq_rslt.GQR_STATUS)
    {
    case Q_OK:
      {
        struct timeval tv;
        int qb_fac;

        gettimeofday (&tv, NULL);
#ifdef LINUX_RQUOTAD_BUG
        /* Since Linux reports a bogus block size value (4k), we must not
         * use it. Thankfully Linux at least always uses 1k block sizes
         * for quota reports, so we just leave away all conversions.
         * If you have a mixed environment, you have a problem though.
         * Complain to the Linux authors or apply my patch (see INSTALL)
         */
        rslt->bhard = gq_rslt.GQR_RQUOTA.rq_bhardlimit;
        rslt->bsoft = gq_rslt.GQR_RQUOTA.rq_bsoftlimit;
        rslt->bcur = gq_rslt.GQR_RQUOTA.rq_curblocks;
#else  /* not buggy */
        if (gq_rslt.GQR_RQUOTA.rq_bsize >= DEV_QBSIZE)
          {
            /* assign first, multiply later:
            ** so that mult works with the possibly larger type in rslt */
            rslt->bhard = gq_rslt.GQR_RQUOTA.rq_bhardlimit;
            rslt->bsoft = gq_rslt.GQR_RQUOTA.rq_bsoftlimit;
            rslt->bcur = gq_rslt.GQR_RQUOTA.rq_curblocks;

            /* we rely on the fact that block sizes are always powers of 2 */
            /* so the conversion factor will never be a fraction */
            qb_fac = gq_rslt.GQR_RQUOTA.rq_bsize / DEV_QBSIZE;
            rslt->bhard *= qb_fac;
            rslt->bsoft *= qb_fac;
            rslt->bcur *= qb_fac;
          }
        else
          {
            if (gq_rslt.GQR_RQUOTA.rq_bsize != 0)
              qb_fac = DEV_QBSIZE / gq_rslt.GQR_RQUOTA.rq_bsize;
            else
              qb_fac = 1;
            rslt->bhard = gq_rslt.GQR_RQUOTA.rq_bhardlimit / qb_fac;
            rslt->bsoft = gq_rslt.GQR_RQUOTA.rq_bsoftlimit / qb_fac;
            rslt->bcur = gq_rslt.GQR_RQUOTA.rq_curblocks / qb_fac;
          }
#endif /* LINUX_RQUOTAD_BUG */
        rslt->fhard = gq_rslt.GQR_RQUOTA.rq_fhardlimit;
        rslt->fsoft = gq_rslt.GQR_RQUOTA.rq_fsoftlimit;
        rslt->fcur = gq_rslt.GQR_RQUOTA.rq_curfiles;

        /* if time is given relative to actual time, add actual time */
        /* Note: all systems except Linux return relative times */
        if (gq_rslt.GQR_RQUOTA.rq_btimeleft == 0)
          rslt->btime = 0;
        else if (gq_rslt.GQR_RQUOTA.rq_btimeleft + 10 * 365 * 24 * 60 * 60
                 < (u_int)tv.tv_sec)
          rslt->btime = tv.tv_sec + gq_rslt.GQR_RQUOTA.rq_btimeleft;
        else
          rslt->btime = gq_rslt.GQR_RQUOTA.rq_btimeleft;

        if (gq_rslt.GQR_RQUOTA.rq_ftimeleft == 0)
          rslt->ftime = 0;
        else if (gq_rslt.GQR_RQUOTA.rq_ftimeleft + 10 * 365 * 24 * 60 * 60
                 < (u_int)tv.tv_sec)
          rslt->ftime = tv.tv_sec + gq_rslt.GQR_RQUOTA.rq_ftimeleft;
        else
          rslt->ftime = gq_rslt.GQR_RQUOTA.rq_ftimeleft;

#if 0
      if((gq_rslt.GQR_RQUOTA.rq_bhardlimit == 0) &&
         (gq_rslt.GQR_RQUOTA.rq_bsoftlimit == 0) &&
         (gq_rslt.GQR_RQUOTA.rq_fhardlimit == 0) &&
         (gq_rslt.GQR_RQUOTA.rq_fsoftlimit == 0)) {
        errno = ESRCH;
	return(-1);
      }
#endif
        return 0;
      }

    case Q_NOQUOTA:
      errno = ESRCH;
      break;

    case Q_EPERM:
      errno = EPERM;
      break;

    default:
      errno = EINVAL;
      break;
    }
  return -1;
}

#ifdef MY_XDR

struct xdr_discrim gq_des[2]
    = { { (int)Q_OK, (xdrproc_t)xdr_rquota }, { 0, NULL } };

bool_t
xdr_getquota_args (xdrs, gqp)
XDR *xdrs;
struct getquota_args *gqp;
{
  return (xdr_string (xdrs, &gqp->gqa_pathp, 1024)
          && xdr_int (xdrs, &gqp->gqa_uid));
}

bool_t
xdr_getquota_rslt (xdrs, gqp)
XDR *xdrs;
struct getquota_rslt *gqp;
{
  return (xdr_union (xdrs, (int *)&gqp->GQR_STATUS, (char *)&gqp->GQR_RQUOTA,
                     gq_des, (xdrproc_t)xdr_void));
}

bool_t
xdr_rquota (xdrs, rqp)
XDR *xdrs;
struct rquota *rqp;
{
  return (xdr_int (xdrs, &rqp->rq_bsize) && xdr_bool (xdrs, &rqp->rq_active)
          && xdr_u_long (xdrs, (unsigned long *)&rqp->rq_bhardlimit)
          && xdr_u_long (xdrs, (unsigned long *)&rqp->rq_bsoftlimit)
          && xdr_u_long (xdrs, (unsigned long *)&rqp->rq_curblocks)
          && xdr_u_long (xdrs, (unsigned long *)&rqp->rq_fhardlimit)
          && xdr_u_long (xdrs, (unsigned long *)&rqp->rq_fsoftlimit)
          && xdr_u_long (xdrs, (unsigned long *)&rqp->rq_curfiles)
          && xdr_u_long (xdrs, (unsigned long *)&rqp->rq_btimeleft)
          && xdr_u_long (xdrs, (unsigned long *)&rqp->rq_ftimeleft));
}
#endif /* MY_XDR */

#ifdef USE_EXT_RQUOTA
bool_t
xdr_ext_getquota_args (xdrs, objp)
XDR *xdrs;
ext_getquota_args *objp;
{
  return xdr_string (xdrs, &objp->gqa_pathp, RQ_PATHLEN)
         && xdr_int (xdrs, &objp->gqa_type) && xdr_int (xdrs, &objp->gqa_id);
}
#endif /* USE_EXT_RQUOTA */

#endif /* !NO_RPC */

query_ret
quota_query (char *dev, int uid, int kind)
{
  query_ret ret;
  char *p = NULL;
  int err;
#ifndef NO_RPC
  quota_rpc_strerror = NULL;
#endif
#ifdef SGI_XFS
  if (!strncmp (dev, "(XFS)", 5))
    {
      fs_disk_quota_t xfs_dqblk;
#ifndef linux
      err = quotactl (Q_XGETQUOTA, dev + 5, uid, CADR & xfs_dqblk);
#else
      err = quotactl (
          QCMD (Q_XGETQUOTA,
                ((kind == 2) ? XQM_PRJQUOTA
                             : ((kind == 1) ? XQM_GRPQUOTA : XQM_USRQUOTA))),
          dev + 5, uid, CADR & xfs_dqblk);
#endif
      if (!err)
        {

          ret.bc = xfs_dqblk.d_bcount;
          ret.bs = xfs_dqblk.d_blk_softlimit;
          ret.bh = xfs_dqblk.d_blk_hardlimit;
          ret.bt = xfs_dqblk.d_btimer;
          ret.fc = xfs_dqblk.d_icount;
          ret.fs = xfs_dqblk.d_ino_softlimit;
          ret.fh = xfs_dqblk.d_ino_hardlimit;
          ret.ft = xfs_dqblk.d_itimer;
        }
    }
  else
#endif
#ifdef SOLARIS_VXFS
      if (!strncmp (dev, "(VXFS)", 6))
    {
      struct vx_dqblk vxfs_dqb;
      err = vx_quotactl (VX_GETQUOTA, dev + 6, uid, CADR & vxfs_dqb);
      if (!err)
        {
          ret.bc = vxfs_dqb.dqb_curblocks;
          ret.bs = xfs_dqb.dqb_bsoftlimit;
          ret.bh = ssvxfs_dqb.dqb_bhardlimit;
          ret.bt = vxfs_dqb.dqb_btimelimit;
          ret.fc = vxfs_dqb.dqb_curfiles;
          ret.fs = vxfs_dqb.dqb_fsoftlimit;
          ret.fh = vxfs_dqb.dqb_fhardlimit;
          ret.ft = vxfs_dqb.dqb_ftimelimit;
        }
    }
  else
#endif
#ifdef AFSQUOTA
      if (!strncmp (dev, "(AFS)", 5))
    {
      if (!afs_check ())
        { /* check is *required* as setup! */
          errno = EINVAL;
        }
      else
        {
          int maxQuota, blocksUsed;

          err = afs_getquota (dev + 5, &maxQuota, &blocksUsed);
          if (!err)
            {
              ret.bc = blocksUsed;
              ret.bs = maxQuota;
              ret.bh = maxQuota;
              ret.bt = 0;
              ret.fc = 0;
              ret.fs = 0;
              ret.fh = 0;
              ret.ft = 0;
            }
        }
    }
  else
#endif
    {
      if ((*dev != '/') && (p = strchr (dev, ':')))
        {
#ifndef NO_RPC
          struct quota_xs_nfs_rslt rslt;
          *p = '\0';
          err = getnfsquota (dev, p + 1, uid, kind, &rslt);
          if (!err)
            {
              ret.bc = rslt.bcur;
              ret.bs = rslt.bsoft;
              ret.bh = rslt.bhard;
              ret.bt = rslt.btime;
              ret.fc = rslt.fcur;
              ret.fs = rslt.fsoft;
              ret.fh = rslt.fhard;
              ret.ft = rslt.ftime;
            }
          *p = ':';
#else  /* NO_RPC */
        errno = ENOTSUP;
        err = -1;
#endif /* NO_RPC */
        }
      else
        {
#ifdef NETBSD_LIBQUOTA
          struct quotahandle *qh = quota_open (dev);
          if (qh != NULL)
            {
              struct quotakey qk_blocks, qk_files;
              struct quotaval qv_blocks, qv_files;

              qk_blocks.qk_idtype = qk_files.qk_idtype
                  = kind ? QUOTA_IDTYPE_GROUP : QUOTA_IDTYPE_USER;
              qk_blocks.qk_id = qk_files.qk_id = uid;
              qk_blocks.qk_objtype = QUOTA_OBJTYPE_BLOCKS;
              qk_files.qk_objtype = QUOTA_OBJTYPE_FILES;

              if ((quota_get (qh, &qk_blocks, &qv_blocks) >= 0)
                  && (quota_get (qh, &qk_files, &qv_files) >= 0))
                {

                  // adapt to common "unlimited" semantics
                  if ((qv_blocks.qv_softlimit == QUOTA_NOLIMIT)
                      && (qv_blocks.qv_hardlimit == QUOTA_NOLIMIT))
                    {
                      qv_blocks.qv_hardlimit = qv_blocks.qv_softlimit = 0;
                    }
                  if ((qv_files.qv_softlimit == QUOTA_NOLIMIT)
                      && (qv_files.qv_hardlimit == QUOTA_NOLIMIT))
                    {
                      qv_files.qv_hardlimit = qv_files.qv_softlimit = 0;
                    }
                  ret.bc = qv_blocks.qv_usage;
                  ret.bs = qv_blocks.qv_softlimit;
                  ret.bh = qv_blocks.qv_hardlimit;
                  ret.bt = qv_blocks.qv_expiretime;
                  ret.fc = qv_files.qv_usage;
                  ret.fs = qv_files.qv_softlimit;
                  ret.fh = qv_files.qv_hardlimit;
                  ret.ft = qv_files.qv_expiretime;
                }
              quota_close (qh);
            }
#else /* not NETBSD_LIBQUOTA */
        struct dqblk dqblk;
#ifdef USE_IOCTL
        struct quotactl qp;
        int fd = -1;

        qp.op = Q_GETQUOTA;
        qp.uid = uid;
        qp.addr = (char *)&dqblk;
        if ((fd = open (dev, O_RDONLY)) != -1)
          {
            err = (ioctl (fd, Q_QUOTACTL, &qp) == -1);
            close (fd);
          }
        else
          {
            err = 1;
          }
#else           /* not USE_IOCTL */
#ifdef Q_CTL_V3 /* Linux */
        err = linuxquota_query (dev, uid, (kind != 0), &dqblk);
#else           /* not Q_CTL_V3 */
#ifdef Q_CTL_V2
#ifdef AIX
        /* AIX quotactl doesn't fail if path does not exist!? */
        struct stat st;
#if defined(HAVE_JFS2)
        if (strncmp (dev, "(JFS2)", 6) == 0)
          {
            if (stat (dev + 6, &st) == 0)
              {
                quota64_t user_quota;

                err = quotactl (
                    dev + 6,
                    QCMD (Q_J2GETQUOTA, ((kind != 0) ? GRPQUOTA : USRQUOTA)),
                    uid, CADR & user_quota);
                if (!err)
                  {
                    ret.bc = user_quota.bused;
                    ret.bs = user_quota.bsoft;
                    ret.bh = user_quota.bhard;
                    ret.bt = user_quota.btime;
                    ret.fc = user_quota.ihard;
                    ret.fs = user_quota.isoft;
                    ret.fh = user_quota.iused;
                    ret.ft = user_quota.itime;
                  }
              }
            err = 1; /* dummy to suppress duplicate push below */
          }
#endif /* HAVE_JFS2 */
        else if (stat (dev, &st))
          {
            err = 1;
          }
        else
#endif /* AIX */
          err = quotactl (
              dev, QCMD (Q_GETQUOTA, ((kind != 0) ? GRPQUOTA : USRQUOTA)), uid,
              CADR & dqblk);
#else  /* not Q_CTL_V2 */
        err = quotactl (Q_GETQUOTA, dev, uid, CADR & dqblk);
#endif /* not Q_CTL_V2 */
#endif /* Q_CTL_V3 */
#endif /* not USE_IOCTL */
        if (!err)
          {
            ret.bc = dqblk.QS_BCUR;
            ret.bs = dqblk.QS_BSOFT;
            ret.bh = dqblk.QS_BHARD;
            ret.bt = dqblk.QS_BTIME;
            ret.fc = dqblk.QS_FCUR;
            ret.fs = dqblk.QS_FSOFT;
            ret.fh = dqblk.QS_FHARD;
            ret.ft = dqblk.QS_FTIME;
          }
#endif /* not NETBSD_LIBQUOTA */
        }
    }
  return ret;
}

int
quota_setqlim (char *dev, int uid, double bs, double bh, double fs, double fh,
               int timelimflag, int kind)
{
  int ret;
  if (timelimflag != 0)
    timelimflag = 1;
#ifndef NO_RPC
  quota_rpc_strerror = NULL;
#endif
#ifdef SGI_XFS
  if (!strncmp (dev, "(XFS)", 5))
    {
      fs_disk_quota_t xfs_dqblk;

      xfs_dqblk.d_blk_softlimit = QX_MUL (bs);
      xfs_dqblk.d_blk_hardlimit = QX_MUL (bh);
      xfs_dqblk.d_btimer = timelimflag;
      xfs_dqblk.d_ino_softlimit = fs;
      xfs_dqblk.d_ino_hardlimit = fh;
      xfs_dqblk.d_itimer = timelimflag;
      xfs_dqblk.d_fieldmask = FS_DQ_LIMIT_MASK;
      xfs_dqblk.d_flags = XFS_USER_QUOTA;
#ifndef linux
      ret = quotactl (Q_XSETQLIM, dev + 5, uid, CADR & xfs_dqblk);
#else
      ret = quotactl (
          QCMD (Q_XSETQLIM,
                ((kind == 2) ? XQM_PRJQUOTA
                             : ((kind == 1) ? XQM_GRPQUOTA : XQM_USRQUOTA))),
          dev + 5, uid, CADR & xfs_dqblk);
#endif
    }
  else
  /* if not xfs, than it's a classic IRIX efs file system */
#endif
#ifdef SOLARIS_VXFS
      if (!strncmp (dev, "(VXFS)", 6))
    {
      struct vx_dqblk vxfs_dqb;

      vxfs_dqb.dqb_bsoftlimit = Q_MUL (bs);
      vxfs_dqb.dqb_bhardlimit = Q_MUL (bh);
      vxfs_dqb.dqb_btimelimit = timelimflag;
      vxfs_dqb.dqb_fsoftlimit = fs;
      vxfs_dqb.dqb_fhardlimit = fh;
      vxfs_dqb.dqb_ftimelimit = timelimflag;
      ret = vx_quotactl (VX_SETQUOTA, dev + 6, uid, CADR & vxfs_dqb);
    }
  else
#endif
#ifdef AFSQUOTA
      if (!strncmp (dev, "(AFS)", 5))
    {
      if (!afs_check ())
        { /* check is *required* as setup! */
          errno = EINVAL;
          ret = -1;
        }
      else
        ret = afs_setqlim (dev + 5, bh);
    }
  else
#endif
#if defined(HAVE_JFS2)
      if (strncmp (dev, "(JFS2)", 6) == 0)
    {
      quota64_t user_quota;

      ret = quotactl (dev + 6,
                      QCMD (Q_J2GETQUOTA, ((kind != 0) ? GRPQUOTA : USRQUOTA)),
                      uid, CADR & user_quota);
      if (ret == 0)
        {
          user_quota.bsoft = bs;
          user_quota.bhard = bh;
          user_quota.btime = timelimflag;
          user_quota.isoft = fs;
          user_quota.ihard = fh;
          user_quota.itime = timelimflag;
          ret = quotactl (
              dev + 6,
              QCMD (Q_J2PUTQUOTA, ((kind != 0) ? GRPQUOTA : USRQUOTA)), uid,
              CADR & user_quota);
        }
    }
  else
#endif /* HAVE_JFS2 */
    {
#ifdef NETBSD_LIBQUOTA
      struct quotahandle *qh;
      struct quotakey qk;
      struct quotaval qv;

      ret = -1;
      qh = quota_open (dev);
      if (qh != NULL)
        {
          qk.qk_idtype = kind ? QUOTA_IDTYPE_GROUP : QUOTA_IDTYPE_USER;
          qk.qk_id = uid;

          qk.qk_objtype = QUOTA_OBJTYPE_BLOCKS;

          /* set the grace period for blocks */
          if (timelimflag)
            { /* seven days */
              qv.qv_grace = 7 * 24 * 60 * 60;
            }
          else if (quota_get (qh, &qk, &qv) >= 0)
            { /* use user's current setting */
              /* OK */
            }
          else if (qk.qk_id = QUOTA_DEFAULTID, quota_get (qh, &qk, &qv) >= 0)
            { /* use default setting */
              /* OK, reset qk_id */
              qk.qk_id = uid;
            }
          else
            {
              qv.qv_grace = 0; /* XXX */
            }

          qv.qv_usage = 0;
          qv.qv_hardlimit = Q_MUL (bh);
          qv.qv_softlimit = Q_MUL (bs);
          qv.qv_expiretime = 0;
          if (quota_put (qh, &qk, &qv) >= 0)
            {
              qk.qk_objtype = QUOTA_OBJTYPE_FILES;

              /* set the grace period for files, see comments above */
              if (timelimflag)
                {
                  qv.qv_grace = 7 * 24 * 60 * 60;
                }
              else if (quota_get (qh, &qk, &qv) >= 0)
                {
                  /* OK */
                }
              else if (qk.qk_id = QUOTA_DEFAULTID,
                       quota_get (qh, &qk, &qv) >= 0)
                {
                  /* OK, reset qk_id */
                  qk.qk_id = uid;
                }
              else
                {
                  qv.qv_grace = 0; /* XXX */
                }

              qv.qv_usage = 0;
              qv.qv_hardlimit = fh;
              qv.qv_softlimit = fs;
              qv.qv_expiretime = 0;
              if (quota_put (qh, &qk, &qv) >= 0)
                {
                  ret = 0;
                }
            }
          quota_close (qh);
        }
#else /* not NETBSD_LIBQUOTA */
    struct dqblk dqblk;
    memset (&dqblk, 0, sizeof (dqblk));
    dqblk.QS_BSOFT = Q_MUL (bs);
    dqblk.QS_BHARD = Q_MUL (bh);
    dqblk.QS_BTIME = timelimflag;
    dqblk.QS_FSOFT = fs;
    dqblk.QS_FHARD = fh;
    dqblk.QS_FTIME = timelimflag;

    // check for truncation of 64-bit value during assignment to 32-bit
    // variable
    if ((sizeof (dqblk.QS_BSOFT) < sizeof (uint64_t))
        && (((uint64_t)bs | (uint64_t)bh | (uint64_t)fs | (uint64_t)fh)
            & 0xFFFFFFFF00000000ULL))
      {
        errno = EINVAL;
        ret = -1;
      }
    else
      {
#ifdef USE_IOCTL
        int fd;
        if ((fd = open (dev, O_RDONLY)) != -1)
          {
            struct quotactl qp;
            qp.op = Q_SETQLIM;
            qp.uid = uid;
            qp.addr = (char *)&dqblk;

            ret = (ioctl (fd, Q_QUOTACTL, &qp) != 0);
            close (fd);
          }
        else
          ret = -1;
#else           /* not USE_IOCTL */
#ifdef Q_CTL_V3 /* Linux */
        ret = linuxquota_setqlim (dev, uid, (kind != 0), &dqblk);
#else           /* not Q_CTL_V3 */
#ifdef Q_CTL_V2
        ret = quotactl (dev,
                        QCMD (Q_SETQUOTA, ((kind != 0) ? GRPQUOTA : USRQUOTA)),
                        uid, CADR & dqblk);
#else
        ret = quotactl (Q_SETQLIM, dev, uid, CADR & dqblk);
#endif /* not Q_CTL_V2 */
#endif /* not Q_CTL_V3 */
#endif /* not USE_IOCTL */
      }
#endif /* not NETBSD_LIBQUOTA */
    }
  return ret;
}

int
quota_sync (char *dev)
{
  int ret;
#ifndef NO_RPC
  quota_rpc_strerror = NULL;
#endif
#ifdef SOLARIS_VXFS
  if ((dev != NULL) && !strncmp (dev, "(VXFS)", 6))
    {
      ret = vx_quotactl (VX_QSYNCALL, dev + 6, 0, NULL);
    }
  else
#endif
#ifdef AFSQUOTA
      if ((dev != NULL) && !strncmp (dev, "(AFS)", 5))
    {
      if (!afs_check ())
        {
          errno = EINVAL;
          ret = -1;
        }
      else
        {
          int foo1, foo2;
          ret = (afs_getquota (dev + 5, &foo1, &foo2) ? -1 : 0);
        }
    }
  else
#endif
#ifdef NETBSD_LIBQUOTA
    ret = 0;
#else /* not NETBSD_LIBQUOTA */
#ifdef USE_IOCTL
  {
    struct quotactl qp;
    int fd;

    if (dev == NULL)
      {
        qp.op = Q_ALLSYNC;
        dev = "/"; /* is probably ignored anyways */
      }
    else
      qp.op = Q_SYNC;
    if ((fd = open (dev, O_RDONLY)) != -1)
      {
        ret = (ioctl (fd, Q_QUOTACTL, &qp) != 0);
        if (errno == ESRCH)
          errno = EINVAL;
        close (fd);
      }
    else
      ret = -1;
  }
#else
  {
#ifdef Q_CTL_V3 /* Linux */
#ifdef SGI_XFS
    if ((dev != NULL) && (!strncmp (dev, "(XFS)", 5)))
      {
        ret = quotactl (QCMD (Q_XQUOTASYNC, XQM_USRQUOTA), dev + 5, 0, NULL);
      }
    else
#endif
      ret = linuxquota_sync (dev, 0);
#else
#ifdef Q_CTL_V2
#ifdef AIX
    struct stat st;
#endif
    if (dev == NULL)
      dev = "/";
#ifdef AIX
#if defined(HAVE_JFS2)
    if (strncmp (dev, "(JFS2)", 6) == 0)
      dev += 6;
#endif
    if (stat (dev, &st))
      ret = -1;
    else
#endif
      ret = quotactl (dev, QCMD (Q_SYNC, USRQUOTA), 0, NULL);
#else
#ifdef SGI_XFS
#define XFS_UQUOTA (XFS_QUOTA_UDQ_ACCT | XFS_QUOTA_UDQ_ENFD)
    /* Q_SYNC is not supported on XFS filesystems, so emulate it */
    if ((dev != NULL) && (!strncmp (dev, "(XFS)", 5)))
      {
        fs_quota_stat_t fsq_stat;

        sync ();

        ret = quotactl (Q_GETQSTAT, dev + 5, 0, CADR & fsq_stat);

        if (!ret && ((fsq_stat.qs_flags & XFS_UQUOTA) != XFS_UQUOTA))
          {
            errno = ENOENT;
            ret = -1;
          }
      }
    else
#endif
      ret = quotactl (Q_SYNC, dev, 0, NULL);
#endif
#endif
    return ret;
  }
#endif
#endif /* NETBSD_LIBQUOTA */
}

query_ret
quota_rpcquery (char *host, char *path, int uid, int kind)
{
  query_ret ret;
#ifndef NO_RPC
  struct quota_xs_nfs_rslt rslt;
  quota_rpc_strerror = NULL;
  if (getnfsquota (host, path, uid, kind, &rslt) == 0)
    {
      ret.bc = rslt.bcur;
      ret.bs = rslt.bsoft;
      ret.bh = rslt.bhard;
      ret.bt = rslt.btime;
      ret.fc = rslt.fcur;
      ret.fs = rslt.fsoft;
      ret.fh = rslt.fhard;
      ret.ft = rslt.ftime;
    }
#else
  errno = ENOTSUP;
#endif
  return ret;
}

void
quota_rpcpeer (unsigned int port, unsigned int use_tcp, unsigned int timeout)
{
#ifndef NO_RPC
  quota_rpc_strerror = NULL;
  quota_rpc_cfg.port = port;
  quota_rpc_cfg.use_tcp = use_tcp;
  quota_rpc_cfg.timeout = timeout;
#endif
}

int
quota_rpcauth (int uid, int gid, char *hostname)
{
  int ret = -1;
#ifndef NO_RPC
  quota_rpc_strerror = NULL;
  if ((uid == -1) && (gid == -1) && (hostname == NULL))
    {
      /* reset to default values */
      quota_rpc_auth.uid = uid;
      quota_rpc_auth.gid = gid;
      quota_rpc_auth.hostname[0] = 0;
      ret = 0;
    }
  else
    {
      if (uid == -1)
        quota_rpc_auth.uid = getuid ();
      else
        quota_rpc_auth.uid = uid;

      if (gid == -1)
        quota_rpc_auth.gid = getgid ();
      else
        quota_rpc_auth.gid = gid;

      if (hostname == NULL)
        {
          ret = gethostname (quota_rpc_auth.hostname, MAX_MACHINE_NAME);
        }
      else if (strlen (hostname) < MAX_MACHINE_NAME)
        {
          strcpy (quota_rpc_auth.hostname, hostname);
          ret = 0;
        }
      else
        {
          errno = EINVAL;
          ret = -1;
        }
    }
#endif
  return ret;
}

int
quota_setmntent ()
{
  int ret;
#ifndef NO_RPC
  quota_rpc_strerror = NULL;
#endif
#ifndef AIX
#ifndef NO_MNTENT
#ifndef NO_OPEN_MNTTAB
  if (mtab != NULL)
    endmntent (mtab);
  if ((mtab = setmntent (MOUNTED, "r")) == NULL)
#else
  if (mtab != NULL)
    fclose (mtab);
  if ((mtab = std_fopen (MOUNTED, "r")) == NULL)
#endif
    ret = -1;
  else
    ret = 0;
#else /* NO_MNTENT */
  /* if(mtab != NULL) free(mtab); */
  if ((mtab_size = getmntinfo (&mtab, MNT_NOWAIT)) <= 0)
    ret = -1;
  else
    ret = 0;
  mntp = mtab;
#endif
#else /* AIX */
  int count, space;

  if (mtab != NULL)
    free (mtab);
  count = mntctl (MCTL_QUERY, sizeof (space), (char *)&space);
  if (count == 0)
    {
      mtab = (struct vmount *)malloc (space);
      if (mtab != NULL)
        {
          count = mntctl (MCTL_QUERY, space, (char *)mtab);
          if (count > 0)
            {
              aix_mtab_count = count;
              aix_mtab_idx = 0;
              ret = 0;
            }
          else
            { /* error, or size changed between calls */
              if (count == 0)
                errno = EINTR;
              ret = -1;
            }
        }
      else
        ret = -1;
    }
  else if (count < 0)
    ret = -1;
  else
    { /* should never happen */
      errno = ENOENT;
      ret = -1;
    }
#endif
  return ret;
}

getmntent_ret
quota_getmntent ()
{
  getmntent_ret ret;
  ret.freemask = 0;
#ifndef NO_RPC
  quota_rpc_strerror = NULL;
#endif
#ifndef AIX
#ifndef NO_MNTENT
#ifndef NO_OPEN_MNTTAB
  struct mntent *mntp;
  if (mtab != NULL)
    {
      mntp = getmntent (mtab);
      if (mntp != NULL)
        {
          ret.dev = mntp->mnt_fsname;
          ret.path = mntp->mnt_dir;
          ret.type = mntp->mnt_type;
          ret.opts = mntp->mnt_opts;
        }
    }
  else
    errno = EBADF;
#else /* NO_OPEN_MNTTAB */
  struct mnttab mntp;
  if (mtab != NULL)
    {
      if (getmntent (mtab, &mntp) == 0)
        {
          ret.dev = mntp.mnt_special;
          ret.path = mntp.mnt_mountp;
          ret.type = mntp.mnt_fstype;
          ret.opts = mntp.mnt_mntopts;
        }
    }
  else
    errno = EBADF;
#endif
#else /* NO_MNTENT */
  if ((mtab != NULL) && mtab_size)
    {
      ret.dev = mntp->f_mntfromname;
      ret.path = mntp->f_mntonname;
#ifdef OSF_QUOTA
      char *fstype = getvfsbynumber ((int)mntp->f_type);
      if (fstype != (char *)-1)
        ret.type = fstype;
      else
#endif
              ret.type = mntp->f_fstypename, strlen(mntp->f_fstypename))));
      */

          char *opts
          = malloc (52);
            snprintf("%s%s%s%s%s%s%s",
                ((mntp->MNTINFO_FLAG_EL & MNT_LOCAL) ? "local" : "non-local"),
                ((mntp->MNTINFO_FLAG_EL & MNT_RDONLY) ? ",read-only" : ""),
                ((mntp->MNTINFO_FLAG_EL & MNT_SYNCHRONOUS) ? ",sync" : ""),
                ((mntp->MNTINFO_FLAG_EL & MNT_NOEXEC) ? ",noexec" : ""),
                ((mntp->MNTINFO_FLAG_EL & MNT_NOSUID) ? ",nosuid" : ""),
                ((mntp->MNTINFO_FLAG_EL & MNT_ASYNC) ? ",async" : ""),
                ((mntp->MNTINFO_FLAG_EL & MNT_QUOTA) ? ",quotas" : ""))));
            );
            ret.opts = opts;
            ret.freemask |= (1 << 3);
            mtab_size--;
            mntp++;
    }
#endif
#else /* AIX */
  struct vmount *vmp;
  char *cp;
  int i;

  if ((mtab != NULL) && (aix_mtab_idx < aix_mtab_count))
    {
      cp = (char *)mtab;
      for (i = 0; i < aix_mtab_idx; i++)
        {
          vmp = (struct vmount *)cp;
          cp += vmp->vmt_length;
        }
      vmp = (struct vmount *)cp;
      aix_mtab_idx += 1;

      if ((vmp->vmt_gfstype != MNT_NFS) && (vmp->vmt_gfstype != MNT_NFS3))
        {
          cp = vmt2dataptr (vmp, VMT_OBJECT);
          ret.dev = cp;
        }
      else
        {
          uchar *mp, *cp2;
          cp = vmt2dataptr (vmp, VMT_HOST);
          cp2 = vmt2dataptr (vmp, VMT_OBJECT);
          mp = malloc (strlen (cp) + strlen (cp2) + 2);
          if (mp != NULL)
            {
              strcpy (mp, cp);
              strcat (mp, ":");
              strcat (mp, cp2);
              ret.dev = mp;
              ret.freemask |= (1 << 0);
            }
          else
            {
              free (mp);
              cp = "?";
              ret.dev = cp;
            }
        }
      cp = vmt2dataptr (vmp, VMT_STUB);
      ret.path = cp;

      switch (vmp->vmt_gfstype)
        {
        case MNT_NFS:
          cp = "nfs";
          break;
        case MNT_NFS3:
          cp = "nfs";
          break;
        case MNT_JFS:
          cp = "jfs";
          break;
#if defined(MNT_AIX) && defined(MNT_J2) && (MNT_AIX == MNT_J2)
        case MNT_J2:
          cp = "jfs2";
          break;
#else
#if defined(MNT_J2)
        case MNT_J2:
          cp = "jfs2";
          break;
#endif
        case MNT_AIX:
          cp = "aix";
          break;
#endif
        case 4:
          cp = "afs";
          break;
        case MNT_CDROM:
          cp = "cdrom,ignore";
          break;
        default:
          cp = "unknown,ignore";
          break;
        }
      ret.type = cp;

      cp = vmt2dataptr (vmp, VMT_ARGS);
      ret.opts = cp;
    }
#endif

  return ret;
}

void
quota_getmntent_free (getmntent_ret ret)
{
  if (ret.freemask & (1 << 0))
    {
      free (ret.dev);
    }
  if (ret.freemask & (1 << 1))
    {
      free (ret.path);
    }
  if (ret.freemask & (1 << 2))
    {
      free (ret.type);
    }
  if (ret.freemask & (1 << 3))
    {
      free (ret.opts);
    }
}

void
quota_endmntent ()
{
#ifndef NO_RPC
  quota_rpc_strerror = NULL;
#endif
  if (mtab != NULL)
    {
#ifndef AIX
#ifndef NO_MNTENT
#ifndef NO_OPEN_MNTTAB
      endmntent (mtab); /* returns always 1 in SunOS */
#else
      std_fclose (mtab);
#endif
      /* #else: if(mtab != NULL) free(mtab); */
#endif
#else /* AIX */
      free (mtab);
#endif
      mtab = NULL;
    }
}

char *
quota_getqcargtype ()
{
  char *ret;
  static char ret[25];
#if defined(USE_IOCTL) || defined(QCARG_MNTPT)
  strcpy (ret, "mntpt");
#else
#if defined(HAVE_JFS2)
  strcpy (ret, "any,JFS2");
#else
#if defined(AIX) || defined(OSF_QUOTA)
  strcpy (ret, "any");
#else
#ifdef Q_CTL_V2
  strcpy (ret, "qfile");
#else
/* this branch applies to Q_CTL_V3 (Linux) too */
#ifdef SGI_XFS
  strcpy (ret, "dev,XFS");
#else
  strcpy (ret, "dev");
#endif
#endif
#endif
#endif
#endif
#ifdef AFSQUOTA
  strcat (ret, ",AFS");
#endif
#ifdef SOLARIS_VXFS
  strcat (ret, ",VXFS");
#endif
  ret = ret;
  return ret;
}

const char *
quota_strerr ()
{
  const char *ret = NULL;
#ifndef NO_RPC
  if (quota_rpc_strerror != NULL)
    ret = quota_rpc_strerror;
  else
#endif
    // ENOENT for (XFS): "No quota for this user"
    if ((errno == EINVAL) || (errno == ENOTTY) || (errno == ENOENT)
        || (errno == ENOSYS))
      ret = "No quotas on this system";
    else if (errno == ENODEV)
      ret = "Not a standard file system";
    else if (errno == EPERM)
      ret = "Not privileged";
    else if (errno == EACCES)
      ret = "Access denied";
    else if (errno == ESRCH)
#ifdef Q_CTL_V3 /* Linux */
      ret = "Quotas not enabled, no quota for this user";
#else
    ret = "No quota for this user";
#endif
    else if (errno == EUSERS)
      ret = "Quota table overflow";
    else
      ret = strerror (errno);
  errno = 0;
  return ret;
}
