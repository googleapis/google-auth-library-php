<?php
/*
 * Copyright 2015 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Google\Auth\Tests;

use Google\Auth\CacheTrait;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;

class CacheTraitTest extends TestCase
{
    use ProphecyTrait;

    private $mockFetcher;
    private $mockCacheItem;
    private $mockCache;

    public function setUp(): void
    {
        $this->mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');
        $this->mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $this->mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
    }

    public function testSuccessfullyPullsFromCache()
    {
        $expectedValue = '1234';
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($expectedValue);
        $this->mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());

        $implementation = new CacheTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);

        $cachedValue = $implementation->getCachedValue('key');
        $this->assertEquals($expectedValue, $cachedValue);
    }

    public function testSuccessfullyPullsFromCacheWithInvalidKey()
    {
        $key = 'this-key-has-@-illegal-characters';
        $expectedKey = 'thiskeyhasillegalcharacters';
        $expectedValue = '1234';
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($expectedValue);
        $this->mockCache->getItem($expectedKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());

        $implementation = new CacheTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);

        $cachedValue = $implementation->getCachedValue($key);
        $this->assertEquals($expectedValue, $cachedValue);
    }

    public function testSuccessfullyPullsFromCacheWithLongKey()
    {
        $key = 'this-key-is-over-64-characters-and-it-will-still-work'
            . '-but-it-will-be-hashed-and-shortened';
        $expectedKey = str_replace('-', '', $key);
        $expectedKey = substr(hash('sha256', $expectedKey), 0, 64);
        $expectedValue = '1234';
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($expectedValue);
        $this->mockCache->getItem($expectedKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());

        $implementation = new CacheTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);

        $cachedValue = $implementation->getCachedValue($key);
        $this->assertEquals($expectedValue, $cachedValue);
    }

    public function testFailsPullFromCacheWithNoCache()
    {
        $implementation = new CacheTraitImplementation();

        $cachedValue = $implementation->getCachedValue('key');
        $this->assertEquals(null, $cachedValue);
    }

    public function testFailsPullFromCacheWithoutKey()
    {
        $implementation = new CacheTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);

        $cachedValue = $implementation->getCachedValue(null);
        $this->assertEquals(null, $cachedValue);
    }

    public function testSuccessfullySetsToCache()
    {
        $value = '1234';
        $this->mockCacheItem->set($value)
            ->shouldBeCalled()
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCacheItem->expiresAfter(Argument::any())
            ->shouldBeCalled()
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->getItem('key')
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalled();

        $implementation = new CacheTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);

        $implementation->setCachedValue('key', $value);
    }

    public function testFailsSetToCacheWithNoCache()
    {
        $implementation = new CacheTraitImplementation();

        $implementation->setCachedValue('key', '1234');

        $cachedValue = $implementation->getCachedValue('key', '1234');
        $this->assertNull($cachedValue);
    }

    public function testFailsSetToCacheWithoutKey()
    {
        $implementation = new CacheTraitImplementation([
            'cache' => $this->mockCache->reveal(),
            'key'   => null,
        ]);

        $cachedValue = $implementation->setCachedValue(null, '1234');
        $this->assertNull($cachedValue);
    }
}

class CacheTraitImplementation
{
    use CacheTrait {
        getCachedValue as public;
        setCachedValue as public;
    }

    public function __construct(array $config = [])
    {
        $this->cache = $config['cache'] ?? null;
        $this->cacheConfig = [
            'prefix' => '',
            'lifetime' => 1000,
        ];
    }
}
