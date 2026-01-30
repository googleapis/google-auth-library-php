<?php

namespace Google\Auth\Tests;

use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use Google\Auth\TrustBoundaryTrait;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

class TrustBoundaryTraitTest extends TestCase
{
    private $impl;

    public function setUp(): void
    {
        $this->impl = new TrustBoundaryTraitImpl();
    }

    public function testBuildTrustBoundaryLookupUrl()
    {
        $url = $this->impl->buildTrustBoundaryLookupUrlPublic('test@example.com');
        $this->assertEquals(
            'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/test@example.com/?recursive=true',
            $url
        );
    }

    public function testLookupTrustBoundary()
    {
        $responseBody = '{"token": "my-token", "authority_selector": "my-selector"}';
        $mock = new MockHandler([
            new Response(200, [], $responseBody),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));
        $result = $this->impl->lookupTrustBoundaryPublic($handler, 'default');
        $this->assertEquals(json_decode($responseBody, true), $result);
    }

    public function testLookupTrustBoundary404()
    {
        $mock = new MockHandler([
            new Response(404),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));
        $result = $this->impl->lookupTrustBoundaryPublic($handler, 'default');
        $this->assertNull($result);
    }

    public function testRefreshTrustBoundaryWithCache()
    {
        $cache = new MemoryCacheItemPool();
        $this->impl->setCache($cache);
        $responseBody = '{"token": "my-token", "authority_selector": "my-selector"}';
        $mock = new MockHandler([
            new Response(200, [], $responseBody),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));

        // First call, should fetch and cache
        $result1 = $this->impl->refreshTrustBoundaryPublic($handler, 'default');
        $this->assertEquals(json_decode($responseBody, true), $result1);

        // Second call, should return from cache
        $mock->reset();
        $mock->append(new Response(500)); // This should not be called
        $result2 = $this->impl->refreshTrustBoundaryPublic($handler, 'default');
        $this->assertEquals(json_decode($responseBody, true), $result2);
    }
}

class TrustBoundaryTraitImpl
{
    use TrustBoundaryTrait {
        buildTrustBoundaryLookupUrl as public buildTrustBoundaryLookupUrlPublic;
        lookupTrustBoundary as public lookupTrustBoundaryPublic;
        refreshTrustBoundary as public refreshTrustBoundaryPublic;
    }

    private $cache;
    private $cacheConfig;

    public function __construct(array $config = [])
    {
        $this->cacheConfig = [
            'prefix' => '',
            'lifetime' => 1000,
        ];
    }

    public function getCacheKey()
    {
        return 'test-key';
    }

    public function setCache($cache)
    {
        $this->cache = $cache;
    }
}
