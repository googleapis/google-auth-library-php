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

namespace Google\Auth;

use GuzzleHttp\Collection;
use GuzzleHttp\Event\RequestEvents;
use GuzzleHttp\Event\SubscriberInterface;
use GuzzleHttp\Event\BeforeEvent;
use GuzzleHttp\ClientInterface;

/**
 * AuthTokenFetcher is a Guzzle Subscriber that adds an Authorization header
 * provided by an object implementing FetchAuthTokenInterface.
 *
 * The FetchAuthTokenInterface#fetchAuthToken is used to obtain a hash; one of
 * the values value in that hash is added as the authorization header.
 *
 * Requests will be accessed with the authorization header:
 *
 * 'Authorization' 'Bearer <value of auth_token>'
 */
class AuthTokenFetcher implements SubscriberInterface
{
  const DEFAULT_CACHE_LIFETIME = 1500;

  /** @var An implementation of CacheInterface */
  private $cache;

  /** @var An implementation of ClientInterface */
  private $client;

  /** @var An implementation of FetchAuthTokenInterface */
  private $fetcher;

  /** @var cache configuration */
  private $cacheConfig;

  /**
   * Creates a new AuthTokenFetcher plugin.
   *
   * @param FetchAuthTokenInterface $fetcher is used to fetch the auth token
   * @param array $cacheConfig configures the cache
   * @param CacheInterface $cache (optional) caches the token.
   * @param ClientInterface $client (optional) http client to fetch the token.
   */
  public function __construct(FetchAuthTokenInterface $fetcher,
                              array $cacheConfig = null,
                              CacheInterface $cache = null,
                              ClientInterface $client = null)
  {
    $this->fetcher = $fetcher;
    $this->client = $client;
    if (!is_null($cache)) {
      $this->cache = $cache;
      $this->cacheConfig = Collection::fromConfig($cacheConfig, [
          'lifetime' => self::DEFAULT_CACHE_LIFETIME,
          'prefix'   => ''
      ], []);
    }
  }

  /* Implements SubscriberInterface */
  public function getEvents()
  {
    return ['before' => ['onBefore', RequestEvents::SIGN_REQUEST]];
  }

  /**
   * Updates the request with an Authorization header when auth is 'fetched_auth_token'.
   *
   *   use GuzzleHttp\Client;
   *   use Google\Auth\OAuth2;
   *   use Google\Auth\AuthTokenFetcher;
   *
   *   $config = [..<oauth config param>.];
   *   $oauth2 = new OAuth2($config)
   *   $scoped = new AuthTokenFetcher($oauth2,
   *                                  $cache = new Memcache(),
   *                                  [ 'prefix' => 'OAuth2::' ]);
   *   $client = new Client([
   *      'base_url' => 'https://www.googleapis.com/taskqueue/v1beta2/projects/',
   *      'defaults' => ['auth' => 'google_auth']
   *   ]);
   *
   *   $res = $client->get('myproject/taskqueues/myqueue');
   */
  public function onBefore(BeforeEvent $event)
  {
    // Requests using "auth"="google_auth" will be authorized.
    $request = $event->getRequest();
    if ($request->getConfig()['auth'] != 'google_auth') {
      return;
    }

    // Use the cached value if its available.
    //
    // TODO: correct caching; update the call to setCachedValue to set the expiry
    // to the value returned with the auth token.
    //
    // TODO: correct caching; enable the cache to be cleared.
    $cached = $this->getCachedValue();
    if (!empty($cached)) {
      $request->setHeader('Authorization', 'Bearer ' . $cached);
      return;
    }

    // Fetch the auth token.
    $auth_tokens = $this->fetcher->fetchAuthToken($this->client);
    if (array_key_exists('access_token', $auth_tokens)) {
      $request->setHeader('Authorization', 'Bearer ' . $auth_tokens['access_token']);
      $this->setCachedValue($auth_tokens['access_token']);
    }
  }

  /**
   * Gets the cached value if it is present in the cache when that is
   * available.
   */
  protected function getCachedValue()
  {
    if (is_null($this->cache)) {
      return null;
    }
    $fetcherKey = $this->fetcher->getCacheKey();
    if (is_null($fetcherKey)) {
      return null;
    }
    $key = $this->cacheConfig['prefix'] . $fetcherKey;
    return $this->cache->get($key, $this->cacheConfig['lifetime']);
  }

  /**
   * Saves the value in the cache when that is available.
   */
  protected function setCachedValue($v)
  {
    if (is_null($this->cache)) {
      return;
    }
    $fetcherKey = $this->fetcher->getCacheKey();
    if (is_null($fetcherKey)) {
      return;
    }
    $key = $this->cacheConfig['prefix'] . $fetcherKey;
    $this->cache->set($key, $v);
  }
}
