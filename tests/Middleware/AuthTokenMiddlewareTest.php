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

namespace Google\Auth\Tests\Middleware;

use Google\Auth\FetchAuthTokenCache;
use Google\Auth\Middleware\AuthTokenMiddleware;
use Google\Auth\Tests\BaseTest;
use Google\Auth\UpdateMetadataInterface;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;

class AuthTokenMiddlewareTest extends BaseTest
{
    use ProphecyTrait;

    private $mockFetcher;
    private $mockCacheItem;
    private $mockCache;
    private $mockRequest;

    protected function setUp(): void
    {
        $this->mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');
        $this->mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $this->mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $this->mockRequest = $this->prophesize('GuzzleHttp\Psr7\Request');
    }

    public function testOnlyTouchesWhenAuthConfigScoped()
    {
        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->willReturn([]);
        $this->mockRequest->withHeader()->shouldNotBeCalled();

        $middleware = new AuthTokenMiddleware($this->mockFetcher->reveal());
        $mock = new MockHandler([new Response(200)]);
        $callable = $middleware($mock);
        $callable($this->mockRequest->reveal(), ['auth' => 'not_google_auth']);
    }

    public function testAddsTheTokenAsAnAuthorizationHeader()
    {
        $authResult = ['access_token' => '1/abcdef1234567890'];
        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($authResult);
        $this->mockRequest->withHeader('authorization', 'Bearer ' . $authResult['access_token'])
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockRequest->reveal());

        $this->runTestCase($this->mockFetcher->reveal());
    }

    public function testDoesNotAddAnAuthorizationHeaderOnNoAccessToken()
    {
        $authResult = ['not_access_token' => '1/abcdef1234567890'];
        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($authResult);
        $this->mockRequest->withHeader('authorization', 'Bearer ')
            ->willReturn($this->mockRequest->reveal());

        $this->runTestCase($this->mockFetcher->reveal());
    }

    public function testUsesIdTokenWhenAccessTokenDoesNotExist()
    {
        $token = 'idtoken12345';
        $authResult = ['id_token' => $token];
        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($authResult);
        $this->mockRequest->withHeader('authorization', 'Bearer ' . $token)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockRequest->reveal());

        $this->runTestCase($this->mockFetcher->reveal());

    }

    public function testUsesCachedAccessToken()
    {
        $cacheKey = 'myKey';
        $accessToken = '2/abcdef1234567890';
        $cachedValue = ['access_token' => $accessToken];
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
        $this->mockRequest->withHeader('authorization', 'Bearer ' . $accessToken)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockRequest->reveal());

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $this->runTestCase($cachedFetcher);
    }

    public function testUsesCachedIdToken()
    {
        $cacheKey = 'myKey';
        $idToken = '2/abcdef1234567890';
        $cachedValue = ['id_token' => $idToken];
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
        $this->mockRequest->withHeader('authorization', 'Bearer ' . $idToken)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockRequest->reveal());

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $this->runTestCase($cachedFetcher);
    }

    public function testGetsCachedAuthTokenUsingCacheOptions()
    {
        $prefix = 'test_prefix_';
        $cacheKey = 'myKey';
        $token = '2/abcdef1234567890';
        $cachedValue = ['access_token' => $token];
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
        $this->mockRequest->withHeader('authorization', 'Bearer ' . $token)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockRequest->reveal());

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            ['prefix' => $prefix],
            $this->mockCache->reveal()
        );
        $this->runTestCase($cachedFetcher);
    }

    public function testShouldSaveValueInCacheWithSpecifiedPrefix()
    {
        $prefix = 'test_prefix_';
        $lifetime = '70707';
        $cacheKey = 'myKey';
        $token = '1/abcdef1234567890';
        $cachedValue = ['access_token' => $token];
        $this->mockCacheItem->get()
            ->willReturn(null);
        $this->mockCacheItem->isHit()
            ->willReturn(false);
        $this->mockCacheItem->set($cachedValue)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCacheItem->expiresAfter($lifetime)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->getItem($prefix . $cacheKey)
            ->shouldBeCalled()
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalled();
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);
        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockRequest->withHeader('authorization', 'Bearer ' . $token)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockRequest->reveal());

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            ['prefix' => $prefix, 'lifetime' => $lifetime],
            $this->mockCache->reveal()
        );
        $this->runTestCase($cachedFetcher);
    }

    /**
     * @dataProvider provideShouldNotifyTokenCallback
     */
    public function testShouldNotifyTokenCallback(callable $tokenCallback)
    {
        $prefix = 'test_prefix_';
        $cacheKey = 'myKey';
        $token = '1/abcdef1234567890';
        $cachedValue = ['access_token' => $token];
        $this->mockCacheItem->get()
            ->willReturn(null);
        $this->mockCacheItem->isHit()
            ->willReturn(false);
        $this->mockCacheItem->set($cachedValue)
            ->shouldBeCalled()
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCacheItem->expiresAfter(Argument::any())
            ->shouldBeCalled()
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->getItem($prefix . $cacheKey)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalled();
        $this->mockFetcher->getCacheKey()
            ->willReturn($cacheKey);
        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockFetcher->getLastReceivedToken()
            ->willReturn($cachedValue);
        $this->mockRequest->withHeader(Argument::any(), Argument::any())
            ->willReturn($this->mockRequest->reveal());

        MiddlewareCallback::$expectedKey = $this->getValidKeyName($prefix . $cacheKey);
        MiddlewareCallback::$expectedValue = $token;
        MiddlewareCallback::$called = false;

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            ['prefix' => $prefix],
            $this->mockCache->reveal()
        );
        $middleware = new AuthTokenMiddleware(
            $cachedFetcher,
            null,
            $tokenCallback
        );
        $mock = new MockHandler([new Response(200)]);
        $callable = $middleware($mock);
        $callable($this->mockRequest->reveal(), ['auth' => 'google_auth']);
        $this->assertTrue(MiddlewareCallback::$called);
    }

    public function testAddAuthHeadersFromUpdateMetadata()
    {
        $authResult = [
            'authorization' => 'Bearer 1/abcdef1234567890',
        ];

        $this->mockFetcher->willImplement(UpdateMetadataInterface::class);
        $this->mockFetcher->updateMetadata(Argument::cetera())
            ->shouldBeCalledTimes(1)
            ->willReturn($authResult);
        $this->mockFetcher->getLastReceivedToken()
            ->willReturn(['access_token' => '1/abcdef1234567890']);

        $request = new Request('GET', 'http://foo.com');

        $middleware = new AuthTokenMiddleware($this->mockFetcher->reveal());
        $mockHandlerCalled = false;
        $mock = new MockHandler([function ($request, $options) use ($authResult, &$mockHandlerCalled) {
            $this->assertEquals($authResult['authorization'], $request->getHeaderLine('authorization'));
            $mockHandlerCalled = true;
            return new Response(200);
        }]);
        $callable = $middleware($mock);
        $callable($request, ['auth' => 'google_auth']);
        $this->assertTrue($mockHandlerCalled);
    }

    public function testOverlappingAddAuthHeadersFromUpdateMetadata()
    {
        $authHeaders = [
            'authorization' => 'Bearer 1/abcdef1234567890',
            'x-goog-api-client' => 'extra-value'
        ];

        $request = new Request('GET', 'http://foo.com');

        $this->mockFetcher->willImplement(UpdateMetadataInterface::class);
        $this->mockFetcher->updateMetadata(Argument::cetera())
            ->shouldBeCalledTimes(1)
            ->willReturn($authHeaders);
        $this->mockFetcher->getLastReceivedToken()
            ->willReturn(['access_token' => '1/abcdef1234567890']);

        $middleware = new AuthTokenMiddleware($this->mockFetcher->reveal());

        $mockHandlerCalled = false;
        $mock = new MockHandler([function ($request, $options) use ($authHeaders, &$mockHandlerCalled) {
            $this->assertEquals($authHeaders['authorization'], $request->getHeaderLine('authorization'));
            $this->assertArrayHasKey('x-goog-api-client', $request->getHeaders());
            $mockHandlerCalled = true;
            return new Response(200);
        }]);
        $callable = $middleware($mock);
        $callable($request, ['auth' => 'google_auth']);
        $this->assertTrue($mockHandlerCalled);
    }

    private function runTestCase($fetcher)
    {
        $middleware = new AuthTokenMiddleware($fetcher);
        $mock = new MockHandler([new Response(200)]);
        $callable = $middleware($mock);
        $callable($this->mockRequest->reveal(), ['auth' => 'google_auth']);
    }

    public function provideShouldNotifyTokenCallback()
    {
        MiddlewareCallback::$phpunit = $this;
        $anonymousFunc = function ($key, $value) {
            MiddlewareCallback::staticInvoke($key, $value);
        };
        return [
            ['Google\Auth\Tests\Middleware\MiddlewareCallbackFunction'],
            ['Google\Auth\Tests\Middleware\MiddlewareCallback::staticInvoke'],
            [['Google\Auth\Tests\Middleware\MiddlewareCallback', 'staticInvoke']],
            [$anonymousFunc],
            [[new MiddlewareCallback(), 'staticInvoke']],
            [[new MiddlewareCallback(), 'methodInvoke']],
            [new MiddlewareCallback()],
        ];
    }
}

class MiddlewareCallback
{
    public static $phpunit;
    public static $expectedKey;
    public static $expectedValue;
    public static $called = false;

    public function __invoke($key, $value)
    {
        self::$phpunit->assertEquals(self::$expectedKey, $key);
        self::$phpunit->assertEquals(self::$expectedValue, $value);
        self::$called = true;
    }

    public function methodInvoke($key, $value)
    {
        return $this($key, $value);
    }

    public static function staticInvoke($key, $value)
    {
        $instance = new self();
        return $instance($key, $value);
    }
}

function MiddlewareCallbackFunction($key, $value)
{
    return MiddlewareCallback::staticInvoke($key, $value);
}
