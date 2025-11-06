<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use Google\Auth\Cache\SysVCacheItemPool;

if (count($argv) !== 3) {
    throw new Exception('Usage: sysv_cache_race_condition_writer.php CACHE_KEY VARAIBLE_KEY');
}

$pool = new SysVCacheItemPool(['variableKey' => $argv[2]]);

$key = $argv[1];

$semKey = ftok(__FILE__, 'B');
$semId = sem_get($semKey);
if (sem_acquire($semId)) {
    $item = $pool->getItem($key);
    $value = (int) $item->get();
    $value++;
    usleep(10000); // Simulate some work
    $item->set($value);
    $pool->save($item);

    sem_release($semId);
}
