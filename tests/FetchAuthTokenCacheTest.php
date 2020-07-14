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
use Google\Auth\Cache\MemoryCacheItemPool;
use Prophecy\Argument;

class FetchAuthTokenCacheTest extends BaseTest
{
    private $mockFetcher;
    private $mockSigner;

    protected function setUp()
    {
        $this->mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');
        $this->mockSigner = $this->prophesize('Google\Auth\SignBlobInterface');

        $this->mockFetcher->getCacheKey()
            ->willReturn("mock-fetch-auth-token");
    }

    public function testCachesToken()
    {
        $want = [
            'access_token' => 'testCachesToken-token',
            'expires_in'   => 3600,
        ];

        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($want);

        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            new MemoryCacheItemPool,
        );

        $got = $cachedFetcher->fetchAuthToken();

        $this->assertEquals($want, $got);

        // should hit the cache this time, note the shouldBeCalledTimes(1)
        // above
        $got = $cachedFetcher->fetchAuthToken();

        $this->assertEquals($want, $got);
    }

    public function testCachesTokenWithExpiry()
    {
        $wantFirst = [
            'access_token' => 'testCachesTokenWithExpiry-token-1',
            'expires_in'   => 0,
        ];

        $wantSecond = [
            'access_token' => 'testCachesTokenWithExpiry-token-2',
            'expires_in'   => 3600,
        ];

        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(2)
            ->willReturn($wantFirst, $wantSecond);

        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            new MemoryCacheItemPool,
        );

        $gotFirst = $cachedFetcher->fetchAuthToken();

        $this->assertEquals($wantFirst, $gotFirst);

        $gotSecond = $cachedFetcher->fetchAuthToken();

        $this->assertEquals($wantSecond, $gotSecond);
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
            new MemoryCacheItemPool
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
            new MemoryCacheItemPool
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
            new MemoryCacheItemPool
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

        $fetcher->signBlob('test');
    }

    public function testGetProjectId()
    {
        $projectId = 'foobar';

        $mockFetcher = $this->prophesize('Google\Auth\ProjectIdProviderInterface');
        $mockFetcher->willImplement('Google\Auth\FetchAuthTokenInterface');
        $mockFetcher->getProjectId(null)
            ->shouldBeCalled()
            ->willReturn($projectId);

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            [],
            new MemoryCacheItemPool
        );

        $this->assertEquals($projectId, $fetcher->getProjectId());
    }

    /**
     * @expectedException RuntimeException
     */
    public function testGetProjectIdInvalidFetcher()
    {
        $mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');
        $mockFetcher->getProjectId()
            ->shouldNotbeCalled();

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            [],
            $this->mockCache
        );

        $fetcher->getProjectId();
    }
}
