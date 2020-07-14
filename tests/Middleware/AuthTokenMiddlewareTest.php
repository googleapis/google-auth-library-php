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
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use Prophecy\Argument;

class AuthTokenMiddlewareTest extends BaseTest
{
    private $mockFetcher;
    private $mockRequest;

    protected function setUp()
    {
        $this->onlyGuzzle6And7();

        $this->mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');
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

        // Run the test.
        $middleware = new AuthTokenMiddleware($this->mockFetcher->reveal());
        $mock = new MockHandler([new Response(200)]);
        $callable = $middleware($mock);
        $callable($this->mockRequest->reveal(), ['auth' => 'google_auth']);
    }

    public function testDoesNotAddAnAuthorizationHeaderOnNoAccessToken()
    {
        $authResult = ['not_access_token' => '1/abcdef1234567890'];
        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($authResult);
        $this->mockRequest->withHeader('authorization', 'Bearer ')
            ->willReturn($this->mockRequest->reveal());

        // Run the test.
        $middleware = new AuthTokenMiddleware($this->mockFetcher->reveal());
        $mock = new MockHandler([new Response(200)]);
        $callable = $middleware($mock);
        $callable($this->mockRequest->reveal(), ['auth' => 'google_auth']);
    }

    public function testUsesIdTokenWhenAccessTokenDoesNotExist()
    {
        $token = 'idtoken12345';
        $authResult = ['id_token' => $token];
        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->willReturn($authResult);
        $this->mockRequest->withHeader('authorization', 'Bearer ' . $token)
            ->willReturn($this->mockRequest);

        $middleware = new AuthTokenMiddleware($this->mockFetcher->reveal());
        $mock = new MockHandler([new Response(200)]);
        $callable = $middleware($mock);
        $callable($this->mockRequest->reveal(), ['auth' => 'google_auth']);
    }

    /**
     * @dataProvider provideShouldNotifyTokenCallback
     */
    public function testShouldNotifyTokenCallback(callable $tokenCallback)
    {
        $wantCacheKey  = "cache-key";
        $wantAuthToken = ['access_token' => "1/abcdef1234567890"];

        $this->mockFetcher->getCacheKey()
            ->willReturn($wantCacheKey);

        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->willReturn($wantAuthToken);

        $this->mockRequest->withHeader(Argument::any(), Argument::any())
            ->willReturn($this->mockRequest->reveal());

        MiddlewareCallback::$expectedKey   = $wantCacheKey;
        MiddlewareCallback::$expectedValue = $wantAuthToken['access_token'];
        MiddlewareCallback::$called        = false;

        $middleware = new AuthTokenMiddleware(
            $this->mockFetcher->reveal(),
            null,
            $tokenCallback
        );

        $handler  = new MockHandler([new Response(200)]);
        $callable = $middleware($handler);

        $callable($this->mockRequest->reveal(), ['auth' => 'google_auth']);

        $this->assertTrue(MiddlewareCallback::$called);
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
            [[new MiddlewareCallback, 'staticInvoke']],
            [[new MiddlewareCallback, 'methodInvoke']],
            [new MiddlewareCallback],
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
