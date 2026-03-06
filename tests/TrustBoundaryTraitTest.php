<?php

namespace Google\Auth\Tests;

use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Auth\GetUniverseDomainInterface;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use Google\Auth\TrustBoundaryTrait;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

class TrustBoundaryTraitTest extends TestCase
{
    use ProphecyTrait;

    private $impl;

    public function setUp(): void
    {
        $this->impl = new TrustBoundaryTraitImpl();
    }

    public function testBuildTrustBoundaryLookupUrl()
    {
        $url = $this->impl->buildTrustBoundaryLookupUrl(serviceAccountEmail: 'test@example.com');
        $this->assertEquals(
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@example.com/allowedLocations',
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
        $result = $this->impl->lookupTrustBoundary($handler, 'default', ['Bearer xyz']);
        $this->assertEquals(json_decode($responseBody, true), $result);
    }

    public function testLookupTrustBoundary404()
    {
        $mock = new MockHandler([
            new Response(404),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));
        $result = $this->impl->lookupTrustBoundary($handler, 'default', ['Bearer xyz']);
        $this->assertNull($result);
    }

    public function testRefreshTrustBoundaryWithCache()
    {
        $cache = new MemoryCacheItemPool();
        $this->impl->setCache($cache);
        $responseBody =
            '{"locations": ["us-central1", "us-east1", "europe-west1", "asia-east1"], "encodedLocations": "0xA30"}';
        $mock = new MockHandler([
            new Response(200, [], $responseBody),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));

        // First call, should fetch and cache
        $result1 = $this->impl->getTrustBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            ['authorization' => ['xyz']]
        );
        $this->assertEquals(json_decode($responseBody, true), $result1);

        // Second call, should return from cache
        $mock->reset();
        $mock->append(new Response(500)); // This should not be called
        $result2 = $this->impl->getTrustBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            []
        );
        $this->assertEquals(json_decode($responseBody, true), $result2);
    }

    public function testCacheLifetime()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()->shouldBeCalledOnce()->willReturn(false);
        $cacheItem->set(Argument::any())->shouldBeCalledOnce();
        $cacheItem->expiresAfter(6 * 60 * 60)->shouldBeCalledOnce();

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(2)
            ->willReturn($cacheItem->reveal());
        $cache->save($cacheItem->reveal())->shouldBeCalledOnce();

        $this->impl->setCache($cache->reveal());

        $responseBody =
            '{"locations": ["us-central1", "us-east1", "europe-west1", "asia-east1"], "encodedLocations": "0xA30"}';
        $mock = new MockHandler([
            new Response(200, [], $responseBody),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));

        // First call, should fetch and cache
        $result1 = $this->impl->getTrustBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            ['authorization' => ['xyz']]
        );

        $this->assertNotNull($result1);
        $this->assertEquals(json_decode($responseBody, true), $result1);
    }

    public function testSkipLookupOutsideDefaultUniverseDomain()
    {
        // First call, should fetch and cache
        $result1 = $this->impl->getTrustBoundary(
            'universe.domain',
            fn () => throw new \Exception('Should not be called'),
            'default',
            ['authorization' => ['xyz']]
        );

        $this->assertNull($result1);
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
        $this->enableTrustBoundary = true;
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
