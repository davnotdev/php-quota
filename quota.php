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

    # SAFETY: Returned Data Must be Freed.
    static private function phpStringToFFI(string $s): FFI\CData {
        $d = FFI::new("char[" . (strlen($s) + 1) . "]");
        FFI::memcpy($d, $s, strlen($s) + 1);        
        return $d;
    }

    function __construct(string $library_dir = __DIR__ . "/libquota.so")
    {
        $ffi = FFI::cdef(PHP_QUOTA_DEF, $library_dir);
    }

    function query(string $dev, int $uid, int $kind): QueryRet
    {
        $dev = PHPQuota::phpStringToFFI($dev);
        $query_ret = $this->ffi->quota_query($dev, $uid, $kind);
        FFI::free($dev);

        return new QueryRet(
            $query_ret->bc,
            $query_ret->bs,
            $query_ret->bh,
            $query_ret->bt,
            $query_ret->fc,
            $query_ret->fs,
            $query_ret->fh,
            $query_ret->ft,
        );
    }

    function setqlim(string $dev, int $uid, float $bs, float $bh, float $fs, float $fh, int $timelimflag, int $kind): int
    {
        $dev = PHPQuota::phpStringToFFI($dev);
        $ret = $this->ffi->quota_setqlim($dev, $uid, $bs, $bh, $fs, $fh, $timelimflag, $kind);
        FFI::free($dev);
        
        return $ret;
    }

    function sync(string $dev): int
    {
        $dev = PHPQuota::phpStringToFFI($dev);
        $ret = $this->ffi->quota_sync(dev);
        FFI::free($dev);

        return $ret;
    }

    // TODO: uid=getuid() kind=0
    function rpcquery(string $host, string $path, int $uid, int $kind): QueryRet
    {
        $host = PHPQuota::phpStringToFFI($host);
        $path = PHPQuota::phpStringToFFI($path);
        $query_ret = $this->ffi->quota_rpcquery($host, $path, $uid, $kind);
        FFI::free($host);
        FFI::free($path);
        
        return new QueryRet(
            $query_ret->bc,
            $query_ret->bs,
            $query_ret->bh,
            $query_ret->bt,
            $query_ret->fc,
            $query_ret->fs,
            $query_ret->fh,
            $query_ret->ft,
        );
    }

    function rpcpeer(int $port, int $use_tcp, int $timeout): void
    {
        $this->ffi->quota_rpcpeer($port, $use_tcp, $timeout);
    }

    function rpcauth(int $uid, int $gid, string $hostname): int
    {
        $hostname = PHPQuota::phpStringToFFI($hostname);
        $ret = $this->ffi->quota_rpcauth($uid, $gid, $hostname);
        FFI::free($hostname);
        return $ret;
    }

    function setmntent(): int
    {
        return $this->ffi->quota_setmntent();
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
        
        return $ret;
    }

    function endmntent(): void
    {
        $this->ffi->quota_endmntent();
    }

    function getqcargtype(): string
    {
        $ret = $this->ffi->quota_getqcargtype();
        return FFI::string($ret);
    }

    // TODO: Handle int errors and strerrs
    private function strerr(): string
    {
        // TODO: This may be null.
        $ret = $this->ffi->quota_strerr();
        return FFI::string($ret);
    }

}

