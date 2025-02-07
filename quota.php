<?php

include("def.php");

class QueryRet
{
    public int $bc, $bs, $bh, $bt, $fc, $fs, $fh, $ft;

    function __construct(int $bc, int $bs, int $bh, int $bt, int $fc, int $fs, int $fh, int $ft) {
        $this->bc = $bc;
        $this->bs = $bs;
        $this->bh = $bh;
        $this->bt = $bt;
        $this->fc = $fc;
        $this->fs = $fs;
        $this->fh = $fh;
        $this->ft = $ft;
    }
}

class GetMntentRet
{
    public string $dev, $path, $type, $opts;

    function __construct(string $dev, string $path, string $type, string $opts) {
        $this->dev = $dev;
        $this->path = $path;
        $this->type = $type;
        $this->opts = $opts;
    }
}

class PHPQuota
{
    protected $ffi;

    const RPC_DEFAULT_TIMEOUT = 4000;

    static private function phpStringToFFI(string $s): FFI\CData {
        $csize = strlen($s) + 1;
        $d = FFI::new("char[" . $csize . "]");
        FFI::memset($d, 0, $csize);
        FFI::memcpy($d, $s, $csize - 1);
        return $d;
    }

    private function checkError(): void {
        $maybeErr = $this->ffi->quota_strerr();
        if (!empty($maybeErr) && $maybeErr != "Success") {
            throw new Exception($maybeErr);
        }
    }

    function __construct(string $library_dir = __DIR__ . "/libquota.so")
    {
        $this->ffi = FFI::cdef(PHP_QUOTA_DEF, $library_dir);
    }

    function query(string $dev, int | null $uid = null, int $kind = 0): QueryRet
    {
        $uid = $uid ?? posix_getuid();

        $dev = PHPQuota::phpStringToFFI($dev);
        $queryRet = $this->ffi->quota_query($dev, $uid, $kind);
        $this->checkError();

        return new QueryRet(
            $queryRet->bc,
            $queryRet->bs,
            $queryRet->bh,
            $queryRet->bt,
            $queryRet->fc,
            $queryRet->fs,
            $queryRet->fh,
            $queryRet->ft,
        );
    }

    function setqlim(string $dev, int | null $uid, float $bs, float $bh, float $fs, float $fh, int $timelimflag = 0, int $kind = 0): int
    {
        $uid = $uid ?? posix_getuid();

        $dev = PHPQuota::phpStringToFFI($dev);
        $ret = $this->ffi->quota_setqlim($dev, $uid, $bs, $bh, $fs, $fh, $timelimflag, $kind);
        $this->checkError();
        
        return $ret;
    }

    function sync(string $dev = ""): int
    {
        $dev = PHPQuota::phpStringToFFI($dev);
        $ret = $this->ffi->quota_sync($dev);
        $this->checkError();

        return $ret;
    }

    function rpcquery(string $host, string $path, int | null $uid = null, int $kind = 0): QueryRet
    {
        $uid = $uid ?? posix_getuid();

        $host = PHPQuota::phpStringToFFI($host);
        $path = PHPQuota::phpStringToFFI($path);
        $queryRet = $this->ffi->quota_rpcquery($host, $path, $uid, $kind);
        $this->checkError();
        
        return new QueryRet(
            $queryRet->bc,
            $queryRet->bs,
            $queryRet->bh,
            $queryRet->bt,
            $queryRet->fc,
            $queryRet->fs,
            $queryRet->fh,
            $queryRet->ft,
        );
    }

    function rpcpeer(int $port = 0, bool $use_tcp = false, int $timeout = RPC_DEFAULT_TIMEOUT): void
    {
        $this->ffi->quota_rpcpeer($port, $use_tcp, $timeout);
    }

    function rpcauth(int $uid = -1, int $gid = -1, string $hostname = ""): int
    {
        $hostname = PHPQuota::phpStringToFFI($hostname);
        $ret = $this->ffi->quota_rpcauth($uid, $gid, $hostname);
        $this->checkError();

        return $ret;
    }

    function setmntent(): int
    {
        $ret = $this->ffi->quota_setmntent();
        $this->checkError();
        return $ret;
    }

    function getmntent(): GetMntentRet
    {
        $getmntent_ret = $this->ffi->quota_getmntent();
        $ret = new GetMntentRet(
            FFI::string($getmntent_ret->dev),
            FFI::string($getmntent_ret->path),
            FFI::string($getmntent_ret->type),
            FFI::string($getmntent_ret->opts)
        );
        $this->ffi->quota_getmntent_free($getmntent_ret);
        $this->checkError();
        
        return $ret;
    }

    function endmntent(): void
    {
        $this->ffi->quota_endmntent();
        $this->checkError();
    }

    function getqcargtype(): string
    {
        $ret = $this->ffi->quota_getqcargtype();
        $this->checkError();
        return FFI::string($ret);
    }
}

