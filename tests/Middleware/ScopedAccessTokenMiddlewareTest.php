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

use Google\Auth\Middleware\ScopedAccessTokenMiddleware;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

class ScopedAccessTokenMiddlewareTest extends BaseTest
{
  const TEST_SCOPE = 'https://www.googleapis.com/auth/cloud-taskqueue';

  private $mockCache;
  private $mockRequest;

  protected function setUp()
  {
    $this->onlyGuzzle6();

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

  /**
   * @expectedException InvalidArgumentException
   */
  public function testRequiresScopeAsAStringOrArray()
  {
    $fakeAuthFunc = function ($unused_scopes) {
       return '1/abcdef1234567890';
    };
    new ScopedAccessTokenMiddleware($fakeAuthFunc, new \stdClass());
  }

  public function testAddsTheTokenAsAnAuthorizationHeader()
  {
    $token = '1/abcdef1234567890';
    $fakeAuthFunc = function ($unused_scopes) use ($token) {
       return $token;
    };
    $this->mockRequest
      ->expects($this->once())
      ->method('withHeader')
      ->with('Authorization', 'Bearer ' . $token)
      ->will($this->returnValue($this->mockRequest));

    // Run the test
    $middleware = new ScopedAccessTokenMiddleware($fakeAuthFunc, self::TEST_SCOPE);
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'scoped']);
  }

  public function testUsesCachedAuthToken()
  {
    $cachedValue = '2/abcdef1234567890';
    $fakeAuthFunc = function ($unused_scopes) {
       return '';
    };
    $this->mockCache
        ->expects($this->once())
        ->method('get')
        ->will($this->returnValue($cachedValue));
    $this->mockRequest
      ->expects($this->once())
      ->method('withHeader')
      ->with('Authorization', 'Bearer ' . $cachedValue)
      ->will($this->returnValue($this->mockRequest));

    // Run the test
    $middleware = new ScopedAccessTokenMiddleware(
      $fakeAuthFunc,
      self::TEST_SCOPE,
      [],
      $this->mockCache
    );
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'scoped']);
  }

  public function testGetsCachedAuthTokenUsingCacheOptions()
  {
    $prefix = 'test_prefix:';
    $lifetime = '70707';
    $cachedValue = '2/abcdef1234567890';
    $fakeAuthFunc = function ($unused_scopes) {
       return '';
    };
    $this->mockCache
        ->expects($this->once())
        ->method('get')
        ->with($this->equalTo($prefix . self::TEST_SCOPE),
               $this->equalTo($lifetime))
        ->will($this->returnValue($cachedValue));
    $this->mockRequest
      ->expects($this->once())
      ->method('withHeader')
      ->with('Authorization', 'Bearer ' . $cachedValue)
      ->will($this->returnValue($this->mockRequest));

    // Run the test
    $middleware = new ScopedAccessTokenMiddleware(
      $fakeAuthFunc,
      self::TEST_SCOPE,
      ['prefix' => $prefix, 'lifetime' => $lifetime],
      $this->mockCache
    );
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'scoped']);
  }

  public function testShouldSaveValueInCache()
  {
    $token = '2/abcdef1234567890';
    $fakeAuthFunc = function ($unused_scopes) use ($token) {
       return $token;
    };
    $this->mockCache
        ->expects($this->once())
        ->method('get')
        ->will($this->returnValue(false));
    $this->mockCache
        ->expects($this->once())
        ->method('set')
        ->with($this->equalTo(self::TEST_SCOPE), $this->equalTo($token))
        ->will($this->returnValue(false));
    $this->mockRequest
      ->expects($this->once())
      ->method('withHeader')
      ->with('Authorization', 'Bearer ' . $token)
      ->will($this->returnValue($this->mockRequest));

    // Run the test
    $middleware = new ScopedAccessTokenMiddleware(
      $fakeAuthFunc,
      self::TEST_SCOPE,
      [],
      $this->mockCache
    );
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'scoped']);
  }

  public function testShouldSaveValueInCacheWithSpecifiedPrefix()
  {
    $token = '2/abcdef1234567890';
    $prefix = 'test_prefix:';
    $fakeAuthFunc = function ($unused_scopes) use ($token) {
       return $token;
    };
    $this->mockCache
        ->expects($this->once())
        ->method('get')
        ->will($this->returnValue(false));
    $this->mockCache
        ->expects($this->once())
        ->method('set')
        ->with($this->equalTo($prefix . self::TEST_SCOPE),
               $this->equalTo($token))
        ->will($this->returnValue(false));
    $this->mockRequest
      ->expects($this->once())
      ->method('withHeader')
      ->with('Authorization', 'Bearer ' . $token)
      ->will($this->returnValue($this->mockRequest));

    // Run the test
    $middleware = new ScopedAccessTokenMiddleware(
      $fakeAuthFunc,
      self::TEST_SCOPE,
      ['prefix' => $prefix],
      $this->mockCache
    );
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'scoped']);
  }

  public function testOnlyTouchesWhenAuthConfigScoped()
  {
    $fakeAuthFunc = function ($unused_scopes) {
       return '1/abcdef1234567890';
    };
    $this->mockRequest
      ->expects($this->never())
      ->method('withHeader');

    // Run the test
    $middleware = new ScopedAccessTokenMiddleware($fakeAuthFunc, self::TEST_SCOPE);
    $mock = new MockHandler([new Response(200)]);
    $callable = $middleware($mock);
    $callable($this->mockRequest, ['auth' => 'not_scoped']);
  }
}
