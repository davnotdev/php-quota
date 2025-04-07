<?php

include("def.php");

enum QuotaType: int {
    case User = 0;
    case Group = 1;
}

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
  
    function getBlockUsage(): int {
        return $this->bc;
    }

    function getBlockSoftLimit(): int {
        return $this->bs;
    }

    function getBlockHardLimit(): int {
        return $this->bh;
    }

    function getBlockTimeLimit(): int {
        return $this->bt;
    }

    function getFileUsage(): int {
        return $this->fc;
    }

    function getFileSoftLimit(): int {
        return $this->fs;
    }

    function getFileHardLimit(): int {
        return $this->fh;
    }

    function getFileTimeLimit(): int {
        return $this->ft;
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

/**
 * @implements Iterator<int, GetMntentRet>
 */
class GetMntent implements Iterator
{
    private $valid = true;
    private $position = 0;
    private $array = array();
    private PHPQuota $phpQuota;

    public function __construct(PHPQuota $phpQuota) {
        $this->phpQuota = $phpQuota;
        $this->position = 0;

        $phpQuota->setmntentRaw();
        $this->next();
    }

    /**
     * @return void
     */
    public function __destruct() {
        $this->phpQuota->endmntentRaw();
    }

    public function rewind(): void {
        if ($this->position > 0) {
            $this->position--;
        }
    }

    public function current(): GetMntentRet {
        return $this->array[$this->position];
    }

    public function key(): int {
        return $this->position;
    }

    public function next(): void {
        if (!$this->valid) {
            return;
        }

        if ($this->position < count($this->array) - 1) {
            $this->position++;
            return;
        }

        $ret = $this->phpQuota->getmntentRaw();
        if ($ret == null) {
            $this->valid = false;
        } else {
            array_push($this->array, $ret);
            $this->position++;
        }
    }

    public function valid(): bool {
        return $this->valid;
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

    function query(string $dev, int | null $uid = null, QuotaType $kind = QuotaType::User): QueryRet
    {
        $uid = $uid ?? posix_getuid();

        $dev = PHPQuota::phpStringToFFI($dev);
        $queryRet = $this->ffi->quota_query($dev, $uid, $kind->value);
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

    function setqlim(string $dev, int | null $uid, float $bs, float $bh, float $fs, float $fh, int $timelimflag = 0, QuotaType $kind = QuotaType::User): int
    {
        $uid = $uid ?? posix_getuid();

        $dev = PHPQuota::phpStringToFFI($dev);
        $ret = $this->ffi->quota_setqlim($dev, $uid, $bs, $bh, $fs, $fh, $timelimflag, $kind->value);
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

    function rpcquery(string $host, string $path, int | null $uid = null, QuotaType $kind = QuotaType::User): QueryRet
    {
        $uid = $uid ?? posix_getuid();

        $host = PHPQuota::phpStringToFFI($host);
        $path = PHPQuota::phpStringToFFI($path);
        $queryRet = $this->ffi->quota_rpcquery($host, $path, $uid, $kind->value);
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

    function setmntentRaw(): int
    {
        $ret = $this->ffi->quota_setmntent();
        $this->checkError();
        return $ret;
    }

    function getmntentRaw(): GetMntentRet | null
    {
        $getmntent_ret = $this->ffi->quota_getmntent();
        if (
            is_null($getmntent_ret->dev) || 
            is_null($getmntent_ret->path) ||
            is_null($getmntent_ret->type) ||
            is_null($getmntent_ret->opts)
        ) {
            $this->ffi->quota_getmntent_free($getmntent_ret);
            $this->checkError();
            return null;
        } else {
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
    }

    function endmntentRaw(): void
    {
        $this->ffi->quota_endmntent();
        $this->checkError();
    }

    function getmntent(): GetMntent {
        return new GetMntent($this);
    }

    function getqcargtype(): string
    {
        $ret = $this->ffi->quota_getqcargtype();
        $this->checkError();
        return FFI::string($ret);
    }
}

