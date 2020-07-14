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
use Google\Auth\Cache\MemoryCacheItemPool;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

class CacheTraitTest extends TestCase
{
    private $impl;
    private $fetcher;

    public function setUp()
    {
        $this->impl = new CacheTraitImplementation;
        $this->fetcher = new FetcherImplementation;
    }

    /**
     * @dataProvider cacheKeyProvider
     */
    public function testGetCachedValue($key)
    {
        $want = $this->fetcher->value();
        $got  = $this->impl->getCachedValue($key, $this->fetcher);

        $this->assertSame($want, $got);

        $got = $this->impl->getCachedValue($key, $this->fetcher);

        $this->assertSame($want, $got);

        // sanity check
        $this->assertNotSame($this->fetcher->value(), $got);
    }

    public function cacheKeyProvider()
    {
        return [
            ["a-normal-cache-key"],
            ["this-key-has-@-illegal-characters"],
            ["this-key-is-over-64-characters-and-it-will-still-work-but-it-should-be-hashed-and-shortened"],
        ];
    }

    public function testLifetime()
    {
        $key = "a-key";

        $implWithLifetime = new CacheTraitImplementation(null, ["lifetime" => 0]);

        $wantFirst = $this->fetcher->value();
        $gotFirst  = $implWithLifetime->getCachedValue($key, $this->fetcher);

        $this->assertSame($wantFirst, $gotFirst);

        $wantSecond = $this->fetcher->value();
        $gotSecond  = $implWithLifetime->getCachedValue($key, $this->fetcher);

        $this->assertSame($wantSecond, $gotSecond);

        // sanity check
        $this->assertNotSame($this->fetcher->value(), $gotFirst);
    }

    public function testPrefix()
    {
        $key     = "key-string";
        $prefixA = "prefix-a-";
        $prefixB = "prefix-b-";

        $sharedCache = new MemoryCacheItemPool;

        $implWithPrefixA = new CacheTraitImplementation($sharedCache, ["prefix" => $prefixA]);
        $implWithPrefixB = new CacheTraitImplementation($sharedCache, ["prefix" => $prefixB]);

        $prefixAFetcher = new FetcherImplementation(10);
        $prefixBFetcher = new FetcherImplementation;

        $prefixAWant = $prefixAFetcher->value();
        $prefixAGot  = $implWithPrefixA->getCachedValue($key, $prefixAFetcher);

        $this->assertSame($prefixAWant, $prefixAGot);

        $prefixBWant = $prefixBFetcher->value();
        $prefixBGot  = $implWithPrefixB->getCachedValue($key, $prefixBFetcher);

        $this->assertSame($prefixBWant, $prefixBGot);

        // sanity check
        $this->assertNotSame($prefixAGot, $prefixBGot);
    }

}

class CacheTraitImplementation
{
    use CacheTrait { getCachedValue as public; }

    public function __construct(
        ?CacheItemPoolInterface $cache = null,
        array $config = []
    ) {
        $this->initCacheTrait($cache, $config);
    }

}

class FetcherImplementation
{
    private $iteration;

    public function __construct($iteration = 0)
    {
        $this->iteration = $iteration;
    }

    public function __invoke(CacheItemInterface $item) {
        $value = $this->value();

        $item->set($value);
        $this->iteration++;

        return $value;
    }

    public function value() {
        return "fetcher-implementation-iteration-{$this->iteration}";
    }
}
