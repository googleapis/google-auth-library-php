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

use Google\Auth\FetchAuthTokenCache;
use Prophecy\Argument;

class FetchAuthTokenCacheTest extends BaseTest
{
    private $mockFetcher;
    private $mockCacheItem;
    private $mockCache;
    private $mockSigner;

    protected function setUp()
    {
        $this->mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');
        $this->mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $this->mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $this->mockSigner = $this->prophesize('Google\Auth\SignBlobInterface');
    }

    public function testUsesCachedAuthToken()
    {
        $cacheKey = 'myKey';
        $cachedValue = '2/abcdef1234567890';
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCache->getItem($cacheKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockFetcher->fetchAuthToken()
            ->shouldNotBeCalled();
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $accessToken = $cachedFetcher->fetchAuthToken();
        $this->assertEquals($accessToken, ['access_token' => $cachedValue]);
    }

    public function testGetsCachedAuthTokenUsingCachePrefix()
    {
        $prefix = 'test_prefix_';
        $cacheKey = 'myKey';
        $cachedValue = '2/abcdef1234567890';
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCache->getItem($prefix . $cacheKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockFetcher->fetchAuthToken()
            ->shouldNotBeCalled();
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);

        // Run the test
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            ['prefix' => $prefix],
            $this->mockCache->reveal()
        );
        $accessToken = $cachedFetcher->fetchAuthToken();
        $this->assertEquals($accessToken, ['access_token' => $cachedValue]);
    }

    public function testShouldSaveValueInCacheWithCacheOptions()
    {
        $prefix = 'test_prefix_';
        $lifetime = '70707';
        $cacheKey = 'myKey';
        $token = '1/abcdef1234567890';
        $authResult = ['access_token' => $token];
        $this->mockCacheItem->get(Argument::any())
            ->willReturn(null);
        $this->mockCacheItem->isHit()
            ->willReturn(false);
        $this->mockCacheItem->set($token)
            ->shouldBeCalledTimes(1)
            ->willReturn(false);
        $this->mockCacheItem->expiresAfter($lifetime)
            ->shouldBeCalledTimes(1);
        $this->mockCache->getItem($prefix . $cacheKey)
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalled();
        $this->mockFetcher->getCacheKey()
            ->willReturn($cacheKey);
        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($authResult);

        // Run the test
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            ['prefix' => $prefix, 'lifetime' => $lifetime],
            $this->mockCache->reveal()
        );
        $accessToken = $cachedFetcher->fetchAuthToken();
        $this->assertEquals($accessToken, ['access_token' => $token]);
    }

    public function testGetLastReceivedToken()
    {
        $token = 'foo';

        $mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');
        $mockFetcher->getLastReceivedToken()
            ->shouldBeCalled()
            ->willReturn([
                'access_token' => $token
            ]);

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            [],
            $this->mockCache->reveal()
        );

        $this->assertEquals($token, $fetcher->getLastReceivedToken()['access_token']);
    }

    public function testGetClientName()
    {
        $name = 'test@example.com';

        $this->mockSigner->getClientName(null)
            ->shouldBeCalled()
            ->willReturn($name);

        $fetcher = new FetchAuthTokenCache(
            $this->mockSigner->reveal(),
            [],
            $this->mockCache->reveal()
        );

        $this->assertEquals($name, $fetcher->getClientName());
    }

    public function testSignBlob()
    {
        $stringToSign = 'foobar';
        $signature = 'helloworld';

        $this->mockSigner->willImplement('Google\Auth\FetchAuthTokenInterface');
        $this->mockSigner->signBlob($stringToSign, true)
            ->shouldBeCalled()
            ->willReturn($signature);

        $fetcher = new FetchAuthTokenCache(
            $this->mockSigner->reveal(),
            [],
            $this->mockCache->reveal()
        );

        $this->assertEquals($signature, $fetcher->signBlob($stringToSign, true));
    }

    /**
     * @expectedException RuntimeException
     */
    public function testSignBlobInvalidFetcher()
    {
        $this->mockFetcher->signBlob('test')
            ->shouldNotbeCalled();

        $fetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            [],
            $this->mockCache
        );

        $this->assertEquals($signature, $fetcher->signBlob('test'));
    }
}
