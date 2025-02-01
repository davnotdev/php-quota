<?php
const PHP_QUOTA_DEF = '
#ifndef PHP_QUOTA_H
#define PHP_QUOTA_H

#include <stdint.h>

typedef struct query_ret {
    uint64_t bc,
             bs,
             bh,
             bt,
             fc,
             fs,
             fh,
             ft;
} query_ret;

typedef struct getmntent_ret {
    char *dev,
         *path,
         *type,
         *opts;
    // freemask stores which strings are "owned" by this object and need to be freed.
    // 
    // (freemask & (1 << 0)): dev
    // (freemask & (1 << 1)): path
    // (freemask & (1 << 2)): type
    // (freemask & (1 << 3)): opts
    char freemask;
} getmntent_ret;

// TODO: uid=getuid(), kind=0
query_ret quota_query(char* dev, int uid, int kind);

// TODO: timelimflag=0 kind=0
int quota_setqlim(char* dev, int uid, double bs, double bh, double fs, double fh, int timelimflag, int kind);

// TODO: dev=NULL
int quota_sync(char* dev);

// TODO: uid=getuid() kind=0
query_ret quota_rpcquery(char* host, char* path, int uid, int kind);

// TODO: port=0, use_tcp=false, timeout= RPC_DEFAULT_TIMEOUT
void quota_rpcpeer(unsigned int port, unsigned int use_tcp, unsigned int timeout);

// TODO: uid=-1, gid=-1, hostname=NULL
int quota_rpcauth(int uid, int gid, char* hostname);

int quota_setmntent();

getmntent_ret quota_getmntent();
void quota_getmntent_free(getmntent_ret ret);

void quota_endmntent();

char * quota_getqcargtype();

const char * quota_strerr();

#endif

';
