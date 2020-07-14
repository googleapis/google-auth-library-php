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

use Google\Auth\Cache\MemoryCacheItemPool;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

trait CacheTrait
{

    private $maxKeyLength = 64;

    /** @var ?CacheItemPoolInterface */
    private $cache;

    /** @var array */
    private $cacheConfig;

    private function initCacheTrait(
        ?CacheItemPoolInterface $cache,
        array $cacheConfig = []
    ) {
        $this->cache = $cache ?? new MemoryCacheItemPool;

        $this->cacheConfig = $cacheConfig + [
            'lifetime' => 1500,
            'prefix'   => '',
        ];
    }

    /**
     * Looks up the key in the cache and, on cache miss, calls the $fetcher
     * callback in order to fetch the real value.
     *
     * @param string $key the cache key to lookup
     * @param callable $fetcher a callback of the form
     *        function(CacheItemInterface $item): mixed, to be called on cache
     *        miss
     * @return mixed the cached value
     */
    private function getCachedValue(string $key, callable $fetcher)
    {
        $normalizedKey = $this->getFullCacheKey($key);

        $cacheItem = $this->cache->getItem($normalizedKey);

        if ($cacheItem->isHit())
        {
            return $cacheItem->get();
        }

        // set the default expiry, the callable can override this
        $cacheItem->expiresAfter($this->cacheConfig['lifetime']);

        $result = $fetcher($cacheItem);

        $this->cache->save($cacheItem);

        return $result;
    }

    private function getFullCacheKey($key)
    {
        if (is_null($key)) {
            return;
        }

        $key = $this->cacheConfig['prefix'] . $key;

        // ensure we do not have illegal characters
        $key = preg_replace('|[^a-zA-Z0-9_\.!]|', '', $key);

        // Hash keys if they exceed $maxKeyLength (defaults to 64)
        if ($this->maxKeyLength && strlen($key) > $this->maxKeyLength) {
            $key = substr(hash('sha256', $key), 0, $this->maxKeyLength);
        }

        return $key;
    }
}
