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

use Google\Auth\Middleware\AuthTokenMiddleware;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

class AuthTokenMiddlewareTest extends BaseTest
{
  private $mockFetcher;
  private $mockCache;
  private $mockRequest;

  protected function setUp()
  {
    $this->onlyGuzzle6();

    $this->mockFetcher =
      $this
      ->getMockBuilder('Google\Auth\FetchAuthTokenInterface')
      ->getMock();
    $this->mockCache =
      $this
      ->getMockBuilder('Google\Auth\CacheInterface')
      ->getMock();
    $this->mockRequest =
      $this
      ->getMockBuilder('GuzzleHttp\Psr7\Request')
      ->disableOriginalConstructor()
      ->getMock();
  }

  public function testOnlyTouchesWhenAuthConfigScoped()
  {
    $this->mockFetcher
      ->expects($this->any())
      ->method('fetchAuthToken')
      ->will($this->returnValue([]));
    $this->mockRequest
      ->expects($this->never())
      ->method('withHeader');

    $middleware = new AuthTokenMiddleware($this->mockFetcher);
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'not_google_auth']);
  }

  public function testAddsTheTokenAsAnAuthorizationHeader()
  {
    $authResult = ['access_token' => '1/abcdef1234567890'];
    $this->mockFetcher
        ->expects($this->once())
        ->method('fetchAuthToken')
        ->will($this->returnValue($authResult));
    $this->mockRequest
      ->expects($this->once())
      ->method('withHeader')
      ->with('Authorization', 'Bearer ' . $authResult['access_token'])
      ->will($this->returnValue($this->mockRequest));

    // Run the test.
    $middleware = new AuthTokenMiddleware($this->mockFetcher);
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'google_auth']);
  }

  public function testDoesNotAddAnAuthorizationHeaderOnNoAccessToken()
  {
    $authResult = ['not_access_token' => '1/abcdef1234567890'];
    $this->mockFetcher
        ->expects($this->once())
        ->method('fetchAuthToken')
        ->will($this->returnValue($authResult));
    $this->mockRequest
      ->expects($this->once())
      ->method('withHeader')
      ->with('Authorization', 'Bearer ')
      ->will($this->returnValue($this->mockRequest));

    // Run the test.
    $middleware = new AuthTokenMiddleware($this->mockFetcher);
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'google_auth']);
  }

  public function testUsesCachedAuthToken()
  {
    $cacheKey = 'myKey';
    $cachedValue = '2/abcdef1234567890';
    $this->mockCache
        ->expects($this->once())
        ->method('get')
        ->with($this->equalTo($cacheKey),
               $this->equalTo(AuthTokenMiddleware::DEFAULT_CACHE_LIFETIME))
        ->will($this->returnValue($cachedValue));
    $this->mockFetcher
        ->expects($this->never())
        ->method('fetchAuthToken');
    $this->mockFetcher
        ->expects($this->any())
        ->method('getCacheKey')
        ->will($this->returnValue($cacheKey));
    $this->mockRequest
      ->expects($this->once())
      ->method('withHeader')
      ->with('Authorization', 'Bearer ' . $cachedValue)
      ->will($this->returnValue($this->mockRequest));

    // Run the test.
    $middleware = new AuthTokenMiddleware($this->mockFetcher, [], $this->mockCache);
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'google_auth']);
  }

  public function testGetsCachedAuthTokenUsingCacheOptions()
  {
    $prefix = 'test_prefix:';
    $lifetime = '70707';
    $cacheKey = 'myKey';
    $cachedValue = '2/abcdef1234567890';
    $this->mockCache
        ->expects($this->once())
        ->method('get')
        ->with($this->equalTo($prefix . $cacheKey),
               $this->equalTo($lifetime))
        ->will($this->returnValue($cachedValue));
    $this->mockFetcher
        ->expects($this->never())
        ->method('fetchAuthToken');
    $this->mockFetcher
        ->expects($this->any())
        ->method('getCacheKey')
        ->will($this->returnValue($cacheKey));
    $this->mockRequest
      ->expects($this->once())
      ->method('withHeader')
      ->with('Authorization', 'Bearer ' . $cachedValue)
      ->will($this->returnValue($this->mockRequest));

    // Run the test.
    $middleware = new AuthTokenMiddleware(
      $this->mockFetcher,
      ['prefix' => $prefix, 'lifetime' => $lifetime],
      $this->mockCache
    );
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'google_auth']);
  }

  public function testShouldSaveValueInCacheWithSpecifiedPrefix()
  {
    $token = '1/abcdef1234567890';
    $authResult = ['access_token' => $token];
    $cacheKey = 'myKey';
    $prefix = 'test_prefix:';
    $this->mockCache
        ->expects($this->any())
        ->method('get')
        ->will($this->returnValue(null));
    $this->mockCache
        ->expects($this->once())
        ->method('set')
        ->with($this->equalTo($prefix . $cacheKey),
               $this->equalTo($token))
        ->will($this->returnValue(false));
    $this->mockFetcher
        ->expects($this->any())
        ->method('getCacheKey')
        ->will($this->returnValue($cacheKey));
    $this->mockFetcher
        ->expects($this->once())
        ->method('fetchAuthToken')
        ->will($this->returnValue($authResult));
    $this->mockRequest
      ->expects($this->once())
      ->method('withHeader')
      ->with('Authorization', 'Bearer ' . $token)
      ->will($this->returnValue($this->mockRequest));

    // Run the test.
    $middleware = new AuthTokenMiddleware(
      $this->mockFetcher,
      ['prefix' => $prefix],
      $this->mockCache
    );
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'google_auth']);
  }
}
