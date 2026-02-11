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
        $url = $this->impl->buildTrustBoundaryLookupUrl('test@example.com');
        $this->assertEquals(
            'https://iamcredentials.foo.bar/v1/projects/-/serviceAccounts/test@example.com/allowedLocations',
            $url
        );
    }

    public function testLookupTrustBoundary()
    {
        $responseBody =
            '{"locations": ["us-central1", "us-east1", "europe-west1", "asia-east1"], "enodedLocations": ""0xA30"}';
        $mock = new MockHandler([
            new Response(200, [], $responseBody),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));
        $result = $this->impl->lookupTrustBoundary($handler, 'default', []);
        $this->assertEquals(json_decode($responseBody, true), $result);
    }

    public function testLookupTrustBoundary404()
    {
        $mock = new MockHandler([
            new Response(404),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));
        $result = $this->impl->lookupTrustBoundary($handler, 'default', []);
        $this->assertNull($result);
    }

    public function testRefreshTrustBoundaryWithCache()
    {
        $cache = new MemoryCacheItemPool();
        $this->impl->setCache($cache);
        $responseBody =
            '{"locations": ["us-central1", "us-east1", "europe-west1", "asia-east1"], "enodedLocations": ""0xA30"}';
        $mock = new MockHandler([
            new Response(200, [], $responseBody),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));

        // First call, should fetch and cache
        $result1 = $this->impl->getTrustBoundary('universe.domain', $handler, 'default', []);
        $this->assertEquals(json_decode($responseBody, true), $result1);

        // Second call, should return from cache
        $mock->reset();
        $mock->append(new Response(500)); // This should not be called
        $result2 = $this->impl->getTrustBoundary('universe.domain', $handler, 'default', []);
        $this->assertEquals(json_decode($responseBody, true), $result2);
    }
}

class TrustBoundaryTraitImpl
{
    use TrustBoundaryTrait {
        buildTrustBoundaryLookupUrl as public;
        lookupTrustBoundary as public;
        getTrustBoundary as public;
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

    public function getUniverseDomain()
    {
        return 'foo.bar';
    }
}
