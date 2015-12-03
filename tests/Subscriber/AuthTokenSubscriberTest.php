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

use Google\Auth\Subscriber\AuthTokenSubscriber;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Event\BeforeEvent;
use GuzzleHttp\Transaction;

class AuthTokenSubscriberTest extends BaseTest
{
  private $mockFetcher;
  private $mockCache;

  protected function setUp()
  {
    $this->onlyGuzzle5();

    $this->mockFetcher =
        $this
        ->getMockBuilder('Google\Auth\FetchAuthTokenInterface')
        ->getMock();
    $this->mockCache =
        $this
        ->getMockBuilder('Google\Auth\CacheInterface')
        ->getMock();
  }

  public function testSubscribesToEvents()
  {
    $a = new AuthTokenSubscriber($this->mockFetcher, array());
    $this->assertArrayHasKey('before', $a->getEvents());
  }


  public function testOnlyTouchesWhenAuthConfigScoped()
  {
    $s = new AuthTokenSubscriber($this->mockFetcher, array());
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'not_google_auth']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $s->onBefore($before);
    $this->assertSame($request->getHeader('Authorization'), '');
  }

  public function testAddsTheTokenAsAnAuthorizationHeader()
  {
    $authResult = ['access_token' => '1/abcdef1234567890'];
    $this->mockFetcher
        ->expects($this->once())
        ->method('fetchAuthToken')
        ->will($this->returnValue($authResult));

    // Run the test.
    $a = new AuthTokenSubscriber($this->mockFetcher, array());
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'google_auth']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $a->onBefore($before);
    $this->assertSame($request->getHeader('Authorization'),
                      'Bearer 1/abcdef1234567890');
  }

  public function testDoesNotAddAnAuthorizationHeaderOnNoAccessToken()
  {
    $authResult = ['not_access_token' => '1/abcdef1234567890'];
    $this->mockFetcher
        ->expects($this->once())
        ->method('fetchAuthToken')
        ->will($this->returnValue($authResult));

    // Run the test.
    $a = new AuthTokenSubscriber($this->mockFetcher, array());
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'google_auth']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $a->onBefore($before);
    $this->assertSame($request->getHeader('Authorization'), '');
  }

  public function testUsesCachedAuthToken()
  {
    $cacheKey = 'myKey';
    $cachedValue = '2/abcdef1234567890';
    $this->mockCache
        ->expects($this->once())
        ->method('get')
        ->with($this->equalTo($cacheKey),
               $this->equalTo(AuthTokenSubscriber::DEFAULT_CACHE_LIFETIME))
        ->will($this->returnValue($cachedValue));
    $this->mockFetcher
        ->expects($this->never())
        ->method('fetchAuthToken');
    $this->mockFetcher
        ->expects($this->any())
        ->method('getCacheKey')
        ->will($this->returnValue($cacheKey));

    // Run the test.
    $a = new AuthTokenSubscriber($this->mockFetcher, array(), $this->mockCache);
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'google_auth']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $a->onBefore($before);
    $this->assertSame($request->getHeader('Authorization'),
                      'Bearer 2/abcdef1234567890');
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

    // Run the test
    $a = new AuthTokenSubscriber($this->mockFetcher,
                              array('prefix' => $prefix,
                                    'lifetime' => $lifetime),
                              $this->mockCache);
    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'google_auth']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $a->onBefore($before);
    $this->assertSame($request->getHeader('Authorization'),
                      'Bearer 2/abcdef1234567890');
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

    // Run the test
    $a = new AuthTokenSubscriber($this->mockFetcher,
                              array('prefix' => $prefix),
                              $this->mockCache);

    $client = new Client();
    $request = $client->createRequest('GET', 'http://testing.org',
                                      ['auth' => 'google_auth']);
    $before = new BeforeEvent(new Transaction($client, $request));
    $a->onBefore($before);
    $this->assertSame($request->getHeader('Authorization'),
                      'Bearer 1/abcdef1234567890');
  }
}
