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

use Google\Auth\Subscriber\ScopedAccessTokenSubscriber;
use GuzzleHttp\Client;
use GuzzleHttp\Event\BeforeEvent;
use GuzzleHttp\Transaction;

class ScopedAccessTokenSubscriberTest extends BaseTest
{
  const TEST_SCOPE = 'https://www.googleapis.com/auth/cloud-taskqueue';

  protected function setUp()
  {
    $this->onlyGuzzle5();
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testRequiresScopeAsAStringOrArray()
  {
    $fakeAuthFunc = function ($unused_scopes) {
       return '1/abcdef1234567890';
    };
    new ScopedAccessTokenSubscriber($fakeAuthFunc, new \stdClass(), array());
  }

  public function testSubscribesToEvents()
  {
    $fakeAuthFunc = function ($unused_scopes) {
       return '1/abcdef1234567890';
    };
    $s = new ScopedAccessTokenSubscriber($fakeAuthFunc, self::TEST_SCOPE, array());
    $this->assertArrayHasKey('before', $s->getEvents());
  }

  public function testAddsTheTokenAsAnAuthorizationHeader()
  {
    $fakeAuthFunc = function ($unused_scopes) {
       return '1/abcdef1234567890';
    };
    $s = new ScopedAccessTokenSubscriber($fakeAuthFunc, self::TEST_SCOPE, array());
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'scoped']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $s->onBefore($before);
    $this->assertSame(
      'Bearer 1/abcdef1234567890',
      $request->getHeader('Authorization')
    );
  }

  public function testUsesCachedAuthToken()
  {
    $cachedValue = '2/abcdef1234567890';
    $fakeAuthFunc = function ($unused_scopes) {
       return '';
    };
    $mockCache = $this
                 ->getMockBuilder('Google\Auth\CacheInterface')
                 ->getMock();
    $mockCache
        ->expects($this->once())
        ->method('get')
        ->will($this->returnValue($cachedValue));

    // Run the test
    $s = new ScopedAccessTokenSubscriber($fakeAuthFunc, self::TEST_SCOPE, array(),
                               $mockCache);
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'scoped']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $s->onBefore($before);
    $this->assertSame(
      'Bearer 2/abcdef1234567890',
      $request->getHeader('Authorization')
    );
  }

  public function testGetsCachedAuthTokenUsingCacheOptions()
  {
    $prefix = 'test_prefix:';
    $lifetime = '70707';
    $cachedValue = '2/abcdef1234567890';
    $fakeAuthFunc = function ($unused_scopes) {
       return '';
    };
    $mockCache = $this
                 ->getMockBuilder('Google\Auth\CacheInterface')
                 ->getMock();
    $mockCache
        ->expects($this->once())
        ->method('get')
        ->with($this->equalTo($prefix . self::TEST_SCOPE),
               $this->equalTo($lifetime))
        ->will($this->returnValue($cachedValue));

    // Run the test
    $s = new ScopedAccessTokenSubscriber($fakeAuthFunc, self::TEST_SCOPE,
                               array('prefix' => $prefix,
                                     'lifetime' => $lifetime),
                               $mockCache);
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'scoped']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $s->onBefore($before);
    $this->assertSame(
      'Bearer 2/abcdef1234567890',
      $request->getHeader('Authorization')
    );
  }

  public function testShouldSaveValueInCache()
  {
    $token = '2/abcdef1234567890';
    $fakeAuthFunc = function ($unused_scopes) {
       return '2/abcdef1234567890';
    };
    $mockCache = $this
                 ->getMockBuilder('Google\Auth\CacheInterface')
                 ->getMock();
    $mockCache
        ->expects($this->once())
        ->method('get')
        ->will($this->returnValue(false));
    $mockCache
        ->expects($this->once())
        ->method('set')
        ->with($this->equalTo(self::TEST_SCOPE), $this->equalTo($token))
        ->will($this->returnValue(false));
    $s = new ScopedAccessTokenSubscriber($fakeAuthFunc, self::TEST_SCOPE, array(),
                               $mockCache);
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'scoped']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $s->onBefore($before);
    $this->assertSame(
      'Bearer 2/abcdef1234567890',
      $request->getHeader('Authorization')
    );
  }

  public function testShouldSaveValueInCacheWithSpecifiedPrefix()
  {
    $token = '2/abcdef1234567890';
    $prefix = 'test_prefix:';
    $fakeAuthFunc = function ($unused_scopes) {
       return '2/abcdef1234567890';
    };
    $mockCache = $this
                 ->getMockBuilder('Google\Auth\CacheInterface')
                 ->getMock();
    $mockCache
        ->expects($this->once())
        ->method('get')
        ->will($this->returnValue(false));
    $mockCache
        ->expects($this->once())
        ->method('set')
        ->with($this->equalTo($prefix . self::TEST_SCOPE),
               $this->equalTo($token))
        ->will($this->returnValue(false));

    // Run the test
    $s = new ScopedAccessTokenSubscriber($fakeAuthFunc, self::TEST_SCOPE,
                               array('prefix' => $prefix),
                               $mockCache);
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'scoped']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $s->onBefore($before);
    $this->assertSame(
      'Bearer 2/abcdef1234567890',
      $request->getHeader('Authorization')
    );
  }

  public function testOnlyTouchesWhenAuthConfigScoped()
  {
    $fakeAuthFunc = function ($unused_scopes) {
       return '1/abcdef1234567890';
    };
    $s = new ScopedAccessTokenSubscriber($fakeAuthFunc, self::TEST_SCOPE, array());
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'notscoped']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $s->onBefore($before);
    $this->assertSame('', $request->getHeader('Authorization'));
  }
}
