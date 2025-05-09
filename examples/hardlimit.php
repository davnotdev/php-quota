<?php

include("quota.php");

$php_quota = new PHPQuota();

$limit_kb = 100 * 1024;

# Careful! When running as root, this will default to root user.
$uid = null;

$current_quota = $php_quota->query("/dev/vda1", $uid);

var_dump($current_quota);

$php_quota->setqlim("/dev/vda1", $uid, $current_quota->bs, $limit_kb, $current_quota->fs, $current_quota->fh);
$php_quota->sync("/dev/vda1");
