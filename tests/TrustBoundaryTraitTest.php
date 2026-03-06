<?php

namespace Google\Auth\Tests;

use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Auth\GetUniverseDomainInterface;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use Google\Auth\TrustBoundaryTrait;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
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
        $cacheItem->set(Argument::any())->shouldBeCalledOnce()->willReturn($cacheItem->reveal());
        $cacheItem->expiresAfter(6 * 60 * 60)->shouldBeCalledOnce()->willReturn($cacheItem->reveal());

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem('testkeytrustboundary')
            ->shouldBeCalledTimes(2)
            ->willReturn($cacheItem->reveal());
        $cache->save($cacheItem->reveal())->shouldBeCalledOnce()->willReturn(true);

        $cooldownCacheItem = $this->prophesize(CacheItemInterface::class);
        $cooldownCacheItem->isHit()->shouldBeCalledOnce()->willReturn(false);
        $cache->getItem('testkeytrustboundarycooldown')
            ->shouldBeCalledOnce()
            ->willReturn($cooldownCacheItem->reveal());

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

    public function testLookupIsFailOpen()
    {
        $mock = new MockHandler([
            new RequestException('Error Communicating with Server', new Request('GET', 'test'))
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));

        $this->assertNull($mock->getLastRequest());

        // First call, should fetch and cache
        $result1 = $this->impl->getTrustBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            ['authorization' => ['xyz']]
        );

        // Ensure the request was made and the error was swallowed
        $this->assertNotNull($mock->getLastRequest());
        $this->assertNull($result1);
    }

    public function testSkipLookupDuringCooldown()
    {
        $cache = $this->prophesize(CacheItemPoolInterface::class);

        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()->shouldBeCalledOnce()->willReturn(false);
        $cache->getItem('testkeytrustboundary')
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());

        $cooldownCacheItem = $this->prophesize(CacheItemInterface::class);
        $cooldownCacheItem->isHit()->shouldBeCalledOnce()->willReturn(true);
        $cooldownCacheItem->get()->shouldBeCalledOnce()->willReturn(true);

        $cache->getItem('testkeytrustboundarycooldown')
            ->shouldBeCalledOnce()
            ->willReturn($cooldownCacheItem->reveal());

        $this->impl->setCache($cache->reveal());

        // First call, should fetch and cache
        $result1 = $this->impl->getTrustBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            fn () => throw new \Exception('Should not be called'),
            'default',
            ['authorization' => ['xyz']]
        );

        $this->assertNull($result1);
    }

    public function provideCooldown()
    {
        $fifteenMinutes = 15 * 60; // cooldown increment
        $sixHours = 6 * 60 * 60; // max cooldown
        return [
            [0, $fifteenMinutes],
            [1, $fifteenMinutes * 2],
            [1000, $sixHours],
        ];
    }

    /**
     * @dataProvider provideCooldown
     */
    public function testCooldown(int $attempt, int $expectedExpiry)
    {
        $cache = $this->prophesize(CacheItemPoolInterface::class);

        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()->shouldBeCalledOnce()->willReturn(false);
        $cache->getItem('testkeytrustboundary')
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());

        $cooldownCacheItem = $this->prophesize(CacheItemInterface::class);
        $cooldownCacheItem->isHit()->shouldBeCalledOnce()->willReturn(false);
        $cooldownCacheItem->set(true)->shouldBeCalledOnce()->willReturn($cooldownCacheItem->reveal());
        $cooldownCacheItem->expiresAfter($expectedExpiry)->shouldBeCalledOnce()->willReturn($cooldownCacheItem->reveal());
        $cache->getItem('testkeytrustboundarycooldown')
            ->shouldBeCalledTimes(2)
            ->willReturn($cooldownCacheItem->reveal());
        $cache->save($cooldownCacheItem->reveal())->shouldBeCalledOnce()->willReturn(true);

        $cooldownCacheItemAttempt = $this->prophesize(CacheItemInterface::class);
        if (0 === $attempt) {
            $cooldownCacheItemAttempt->isHit()->shouldBeCalledOnce()->willReturn(false);
        } else {
            $cooldownCacheItemAttempt->isHit()->shouldBeCalledOnce()->willReturn(true);
            $cooldownCacheItemAttempt->get()->shouldBeCalledOnce()->willReturn($attempt);
        }
        $cooldownCacheItemAttempt->set($attempt + 1)->shouldBeCalledOnce()->willReturn($cooldownCacheItemAttempt->reveal());
        $cooldownCacheItemAttempt->expiresAfter($expectedExpiry * 2)->shouldBeCalledOnce()->willReturn($cooldownCacheItemAttempt->reveal());
        $cache->getItem('testkeytrustboundarycooldownattempt')
            ->shouldBeCalledTimes(2)
            ->willReturn($cooldownCacheItemAttempt->reveal());
        $cache->save($cooldownCacheItemAttempt->reveal())->shouldBeCalledOnce()->willReturn(true);

        $this->impl->setCache($cache->reveal());

        $mock = new MockHandler([
            new RequestException('Error Communicating with Server (1)', new Request('GET', 'test')),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));

        // First call, should fetch and cache
        $result1 = $this->impl->getTrustBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
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
