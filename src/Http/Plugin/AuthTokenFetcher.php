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

namespace Google\Auth\Http\Plugin;

use Google\Auth\CacheInterface;
use Google\Auth\FetchAuthTokenInterface;
use Http\Client\HttpClient;
use Http\Client\Plugin\Plugin;
use Http\Client\Plugin\PluginClient;
use Http\Discovery\HttpClientDiscovery;
use Psr\Http\Message\RequestInterface;

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
class AuthTokenFetcher implements Plugin
{
    const DEFAULT_CACHE_LIFETIME = 1500;

  /** @var CacheInterface An implementation of CacheInterface */
  private $cache;

  /** @var HttpClient An implementation of HttpClient */
  private $client;

  /** @var FetchAuthTokenInterface An implementation of FetchAuthTokenInterface */
  private $fetcher;

  /** @var cache configuration */
  private $cacheConfig;

  /**
   * Creates a new AuthTokenFetcher plugin.
   *
   * @param FetchAuthTokenInterface $fetcher is used to fetch the auth token
   * @param array $cacheConfig configures the cache
   * @param CacheInterface $cache (optional) caches the token.
   * @param HttpClient $client (optional) http client to fetch the token.
   */
  public function __construct(
      FetchAuthTokenInterface $fetcher,
      array $cacheConfig = null,
      CacheInterface $cache = null,
      HttpClient $client = null
  ) {
      $this->fetcher = $fetcher;
      $this->client = $client;
      if (!is_null($cache)) {
          $this->cache = $cache;
          $this->cacheConfig = array_merge([
          'lifetime' => self::DEFAULT_CACHE_LIFETIME,
          'prefix' => '',
      ], $cacheConfig);
      }
  }

    public function handleRequest(RequestInterface $request, callable $next, callable $first)
    {
        // Use the cached value if its available.
    //
    // TODO: correct caching; update the call to setCachedValue to set the expiry
    // to the value returned with the auth token.
    //
    // TODO: correct caching; enable the cache to be cleared.
    $token = $this->fetch();
        if (empty($token)) {
            // Fetch the auth token.
      $auth_tokens = $this->fetcher->fetchAuthToken($this->client);
            if (!isset($auth_tokens['access_token'])) {
                // We did not find any access token
        return $next($request);
            }
            $token = $auth_tokens['access_token'];
            $this->storeCachedValue($token);
        }
        $newRequest = $request->withHeader('Authorization', 'Bearer '.$token);

        return $next($newRequest);
    }

  /**
   * Gets the cached value if it is present in the cache when that is
   * available.
   */
  protected function fetch()
  {
      if (is_null($this->cache)) {
          return;
      }

      $fetcherKey = $this->fetcher->getCacheKey();
      if (is_null($fetcherKey)) {
          return;
      }

      $key = $this->cacheConfig['prefix'].$fetcherKey;

      return $this->cache->get($key, $this->cacheConfig['lifetime']);
  }

  /**
   * Saves the value in the cache when that is available.
   *
   * @param mixed $v
   */
  protected function storeCachedValue($v)
  {
      if (is_null($this->cache)) {
          return;
      }

      $fetcherKey = $this->fetcher->getCacheKey();
      if (is_null($fetcherKey)) {
          return;
      }

      $key = $this->cacheConfig['prefix'].$fetcherKey;
      $this->cache->set($key, $v);
  }
}
