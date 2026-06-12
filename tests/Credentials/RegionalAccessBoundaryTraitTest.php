<?php

namespace Google\Auth\Tests;

use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Auth\GetUniverseDomainInterface;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use Google\Auth\Credentials\RegionalAccessBoundaryTrait;
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

class RegionalAccessBoundaryTraitTest extends TestCase
{
    use ProphecyTrait;

    private RegionalAccessBoundaryTraitImpl $impl;

    public function setUp(): void
    {
        $this->impl = new RegionalAccessBoundaryTraitImpl();
    }

    public function testBuildRegionalAccessBoundaryLookupUrl()
    {
        $url = $this->impl->buildRegionalAccessBoundaryLookupUrl(serviceAccountEmail: 'test@example.com');
        $this->assertEquals(
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@example.com/allowedLocations',
            $url
        );
    }

    public function testLookupRegionalAccessBoundary()
    {
        $responseBody =
            '{"locations": ["us-central1", "us-east1", "europe-west1", "asia-east1"], "enodedLocations": ""0xA30"}';
        $handler = getHandler([
            new Response(200, [], $responseBody),
        ]);
        $result = $this->impl->lookupRegionalAccessBoundary($handler, 'default', ['Bearer xyz']);
        $this->assertEquals(json_decode($responseBody, true), $result);
    }

    public function testLookupRegionalAccessBoundary404()
    {
        $handler = getHandler([
            new Response(404)
        ]);
        $result = $this->impl->lookupRegionalAccessBoundary($handler, 'default', ['Bearer xyz']);
        $this->assertNull($result);
    }

    public function testSkipLookupOutsideDefaultUniverseDomain()
    {
        // First call, should fetch and cache
        $result1 = $this->impl->getRegionalAccessBoundary(
            'universe.domain',
            fn () => throw new \Exception('Should not be called'),
            'default',
            ['authorization' => ['xyz']]
        );

        $this->assertNull($result1);
    }

    public function testSkipLookupIfXAllowedLocationsAreAlreadySet()
    {
        // First call, should fetch and cache
        $result1 = $this->impl->getRegionalAccessBoundary(
            'universe.domain',
            fn () => throw new \Exception('Should not be called'),
            'default',
            ['authorization' => ['xyz'], ['x-allowed-locations' => 'abc']]
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
        $result1 = $this->impl->getRegionalAccessBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            ['authorization' => ['xyz']]
        );

        // Ensure the request was made and the error was swallowed
        $this->assertNotNull($mock->getLastRequest());
        $this->assertNull($result1);
    }

    public function testRefreshRegionalAccessBoundaryWithCache()
    {
        $cache = new MemoryCacheItemPool();
        $this->impl->setCache($cache);
        $responseBody =
            '{"locations": ["us-central1", "us-east1", "europe-west1", "asia-east1"], "encodedLocations": "0xA30"}';
        $handler = getHandler([
            new Response(200, [], $responseBody),
        ]);

        // First call, should fetch and cache
        $result1 = $this->impl->getRegionalAccessBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            ['authorization' => ['xyz']]
        );
        $this->assertEquals(json_decode($responseBody, true), $result1);

        // Second call, should return from cache
        $handler = getHandler([
            new Response(500), // This should not be called
        ]);
        $result2 = $this->impl->getRegionalAccessBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            []
        );
        $this->assertEquals(json_decode($responseBody, true), $result2);
    }

    public function testRefreshRegionalAccessBoundaryWithCacheAfterExpiry()
    {
        $cache = new MemoryCacheItemPool();
        $this->impl->setCache($cache);
        $cachedResponseBody =
            '{"locations": ["cached-locations"], "encodedLocations": "0xA30"}';

        $cacheItem = $cache->getItem('testkeyrab');
        $cacheItem->set(json_decode($cachedResponseBody, true));
        $cacheItem->expiresAt(\DateTime::createFromFormat('U', time() + 1)); // in the future
        $cache->save($cacheItem);

        // First call, should fetch from cache
        $result1 = $this->impl->getRegionalAccessBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            fn () => throw new \Exception('Should not be called'),
            'default',
            ['authorization' => ['xyz']]
        );
        $this->assertEquals(json_decode($cachedResponseBody, true), $result1);

        // Set cache to expired
        $cacheItem->expiresAt(\DateTime::createFromFormat('U', time() - 1)); // in the future
        $cache->save($cacheItem);

        // Second call, should return from HTTP call
        $responseBody =
            '{"locations": ["noncached-locations"], "encodedLocations": "0xA30"}';
        $handler = getHandler([
            new Response(200, [], $responseBody),
        ]);

        $result2 = $this->impl->getRegionalAccessBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            ['authorization' => ['xyz']]
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
        $cache->getItem('testkeyrab')
            ->shouldBeCalledTimes(2)
            ->willReturn($cacheItem->reveal());
        $cache->save($cacheItem->reveal())->shouldBeCalledOnce()->willReturn(true);

        $cooldownCacheItem = $this->prophesize(CacheItemInterface::class);
        $cooldownCacheItem->isHit()->shouldBeCalledOnce()->willReturn(false);
        $cache->getItem('testkeyrabcooldown')
            ->shouldBeCalledOnce()
            ->willReturn($cooldownCacheItem->reveal());

        $this->impl->setCache($cache->reveal());

        $responseBody =
            '{"locations": ["us-central1", "us-east1", "europe-west1", "asia-east1"], "encodedLocations": "0xA30"}';
        $handler = getHandler([
            new Response(200, [], $responseBody)
        ]);
        // First call, should fetch and cache
        $result1 = $this->impl->getRegionalAccessBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            ['authorization' => ['xyz']]
        );

        $this->assertNotNull($result1);
        $this->assertEquals(json_decode($responseBody, true), $result1);
    }

    public function testSkipLookupDuringCooldown()
    {
        $cache = $this->prophesize(CacheItemPoolInterface::class);

        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()->shouldBeCalledOnce()->willReturn(false);
        $cache->getItem('testkeyrab')
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());

        $cooldownCacheItem = $this->prophesize(CacheItemInterface::class);
        $cooldownCacheItem->isHit()->shouldBeCalledOnce()->willReturn(true);
        $cooldownCacheItem->get()->shouldBeCalledOnce()->willReturn(true);

        $cache->getItem('testkeyrabcooldown')
            ->shouldBeCalledOnce()
            ->willReturn($cooldownCacheItem->reveal());

        $this->impl->setCache($cache->reveal());

        // First call, should fetch and cache
        $result1 = $this->impl->getRegionalAccessBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            fn () => throw new \Exception('Should not be called'),
            'default',
            ['authorization' => ['xyz']]
        );

        $this->assertNull($result1);
    }

    public function testSkipCooldownAfterExpiry()
    {
        $cache = new MemoryCacheItemPool();

        $cacheItem = $cache->getItem('testkeyrabcooldown');
        $cacheItem->set(true);
        $cacheItem->expiresAt(\DateTime::createFromFormat('U', time() - 1)); // in the past
        $cache->save($cacheItem);

        $this->impl->setCache($cache);

        $result = $this->impl->getRegionalAccessBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            getHandler([new Response(200, [], '{"encodedLocations": "0xA30"}')]),
            'default',
            ['authorization' => ['xyz']]
        );

        $this->assertEquals(['encodedLocations' => '0xA30'], $result);
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
    public function testInitiateCooldown(int $attempt, int $expectedExpiry)
    {
        $cache = $this->prophesize(CacheItemPoolInterface::class);

        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()->shouldBeCalledOnce()->willReturn(false);
        $cache->getItem('testkeyrab')
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());

        $cooldownCacheItem = $this->prophesize(CacheItemInterface::class);
        $cooldownCacheItem->isHit()->shouldBeCalledOnce()->willReturn(false);
        $cooldownCacheItem->set(true)->shouldBeCalledOnce()->willReturn($cooldownCacheItem->reveal());
        $cooldownCacheItem->expiresAfter($expectedExpiry)->shouldBeCalledOnce()->willReturn($cooldownCacheItem->reveal());
        $cache->getItem('testkeyrabcooldown')
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
        $cache->getItem('testkeyrabcooldownattempt')
            ->shouldBeCalledTimes(2)
            ->willReturn($cooldownCacheItemAttempt->reveal());
        $cache->save($cooldownCacheItemAttempt->reveal())->shouldBeCalledOnce()->willReturn(true);

        $this->impl->setCache($cache->reveal());

        $mock = new MockHandler([
            new RequestException('Error Communicating with Server (1)', new Request('GET', 'test')),
        ]);
        $handler = HttpHandlerFactory::build(new Client(['handler' => $mock]));

        // First call, should fetch and cache
        $result1 = $this->impl->getRegionalAccessBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            ['authorization' => ['xyz']]
        );

        $this->assertNull($result1);
    }

    public function provideMalformedResponseFromAllowLocationsLookup()
    {
        return [
            [200, '{"locations": ["us-west1"]}'], // missing allowLocations
            [200, '{"locations": ["us-west1"]'],  // invalid JSON
            [401, ''],                            // 4xx error
            [500, ''],                            // 5xx error
        ];
    }

    /**
     * @dataProvider provideMalformedResponseFromAllowLocationsLookup
     */
    public function testMalformedResponseFromAllowLocationsLookup(int $statusCode, string $responseBody)
    {
        $this->impl->setCache(new MemoryCacheItemPool());
        $handler = getHandler([
            new Response($statusCode, [], $responseBody),
        ]);
        $result = $this->impl->getRegionalAccessBoundary(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $handler,
            'default',
            ['authorization' => ['xyz']]
        );

        $this->assertNull($result);
        $this->assertTrue($this->impl->cooldownIsActive());
    }
}

class RegionalAccessBoundaryTraitImpl
{
    use RegionalAccessBoundaryTrait {
        buildRegionalAccessBoundaryLookupUrl as public;
        lookupRegionalAccessBoundary as public;
        getRegionalAccessBoundary as public;
    }

    private $cache;
    private $cacheConfig;

    public function __construct(array $config = [])
    {
        $this->cacheConfig = [
            'prefix' => '',
            'lifetime' => 1000,
        ];
        $this->enableRegionalAccessBoundary = true;
    }

    public function getCacheKey()
    {
        return 'test-key';
    }

    public function setCache($cache)
    {
        $this->cache = $cache;
    }

    public function cooldownIsActive(): bool
    {
        return (bool) $this->getCachedValue($this->getCacheKey() . ':rab:cooldown');
    }
}
