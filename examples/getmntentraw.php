<?php

include("quota.php");

$php_quota = new PHPQuota();

$php_quota->setmntentRaw();

while (true) {
    $mnt = $php_quota->getmntentRaw();

    if (is_null($mnt)) {
        break;
    }

    var_dump($mnt);
}

$php_quota->endmntentRaw();

