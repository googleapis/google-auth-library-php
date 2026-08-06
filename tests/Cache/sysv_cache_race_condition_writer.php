<?php

$file = dirname(__DIR__, 2) . '/vendor/autoload.php';
if (!file_exists($file)) {
    $file = dirname(__DIR__, 3) . '/vendor/autoload.php';
    if (!file_exists($file)) {
        throw new \Exception('composer autoload.php not found');
    }
}
require_once $file;

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
