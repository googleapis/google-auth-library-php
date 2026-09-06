<?php

$file = dirname(__DIR__, 2) . '/vendor/autoload.php';
if (!file_exists($file)) {
    $file = dirname(__DIR__, 3) . '/vendor/autoload.php';
    if (!file_exists($file)) {
        throw new \Exception('composer autoload.php not found');
    }
}
require_once $file;
require_once __DIR__ . '/TestFileCacheItemPool.php';

use Google\Auth\FetchAuthTokenCache;
use Google\Auth\FetchAuthTokenInterface;
use Google\Auth\GetUniverseDomainInterface;
use Google\Auth\Tests\TestFileCacheItemPool;

$cache = new TestFileCacheItemPool(sys_get_temp_dir() . '/google-auth-test');

$fetcher = new class($argv[1]) implements FetchAuthTokenInterface, GetUniverseDomainInterface {
    private $cacheKey;

    public function __construct(string $cacheKey)
    {
        $this->cacheKey = $cacheKey;
    }

    public function getUniverseDomain(): string
    {
        throw new \Exception('Should not be called!');
    }

    public function getCacheKey()
    {
        return $this->cacheKey;
    }

    // no op
    public function fetchAuthToken(?callable $httpHandle = null)
    {
    }
    // no op
    public function getLastReceivedToken()
    {
    }
};

$cacheFetcher = new FetchAuthTokenCache(
    $fetcher,
    ['cacheUniverseDomain' => true],
    $cache
);

echo $cacheFetcher->getUniverseDomain();
