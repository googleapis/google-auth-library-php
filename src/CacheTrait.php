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

use Psr\Cache\CacheItemPoolInterface;

trait CacheTrait
{
    /**
     * @var int
     */
    private $maxKeyLength = 64;

    /**
     * @var array<mixed>
     */
    private $cacheConfig;

    /**
     * @var ?CacheItemPoolInterface
     */
    private $cache;

    /**
     * Gets the cached value if it is present in the cache when that is
     * available.
     *
     * @param mixed $k
     *
     * @return mixed
     */
    private function getCachedValue($k)
    {
        if (is_null($this->cache)) {
            return null;
        }

        $key = $this->getFullCacheKey($k);
        if (is_null($key)) {
            return null;
        }

        $cacheItem = $this->cache->getItem($key);
        if ($cacheItem->isHit()) {
            return $cacheItem->get();
        }
    }

    /**
     * Saves the value in the cache when that is available.
     *
     * @param mixed $k
     * @param mixed $v
     * @return mixed
     */
    private function setCachedValue($k, $v)
    {
        if (is_null($this->cache)) {
            return null;
        }

        $key = $this->getFullCacheKey($k);
        if (is_null($key)) {
            return null;
        }

        $cacheItem = $this->cache->getItem($key);
        $cacheItem->set($v);
        $cacheItem->expiresAfter($this->cacheConfig['lifetime']);
        return $this->cache->save($cacheItem);
    }

    /**
     * @param null|string $key
     * @return null|string
     */
    private function getFullCacheKey($key)
    {
        if (is_null($key)) {
            return null;
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
