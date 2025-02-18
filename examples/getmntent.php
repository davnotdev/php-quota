<?php

include("quota.php");

$php_quota = new PHPQuota();

foreach ($php_quota->getmntent() as $_=>$mnt) {
    var_dump($mnt);
}

