<?php
/**
 * Copyright 2024 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 namespace Google\Auth\Cache;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

 class CacheChain implements CacheItemPoolInterface
 {
    private array $pools = [];

    /**
     * @param CacheItemPoolInterface[] $pools 
     */
    public function __construct(array $pools)
    {
        foreach($pools as $pool) {
            $this->addPool($pool);
        }
    }

    public function getItem(string $key): CacheItemInterface
    {
        foreach($this->pools as $pool) {
            $item = $pool->getItem($key);
            if ($item->isHit()) {
                return $item;
            }
        }

        return new TypedItem($$key);
    }

    public function getItems(array $keys = []): iterable
    {
        $result = [];

        foreach($keys as $key) {
            $result[$key] = $this->getItem($key);
        }

        return $result;
    }

    public function hasItem(string $key): bool
    {
        foreach($this->pools as $pool) {
            if($pool->hasItem($key)) {
                return true;
            }
        }

        return false;
    }

    public function clear(): bool
    {
        $result = true;

        foreach($this->pools as $pool) {
            if(!$pool->clear()) {
                $result = false;
            }
        }

        return $result;
    }

    public function deleteItem(string $key): bool
    {
        $result = true;
        
        foreach($this->pools as $pool) {
            if(!$pool->deleteItem($key)) {
                $result = false;
            }
        }

        return $result;
    }

    public function deleteItems(array $keys): bool
    {
        $result = true;
        
        foreach($keys as $key) {
            if(!$this->deleteItem($key)) {
                $result = false;
            }
        }

        return $result;
    }

    public function save(CacheItemInterface $item): bool
    {
        $result = true;

        foreach($this->pools as $pool) {
            if(!$pool->save($item)) {
                $result = false;
            }
        }

        return $result;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        $result = true;

        foreach($this->pools as $pool) {
            if(!$pool->saveDeferred($item)) {
                $result = false;
            }
        }

        return $result;
    }

    public function commit(): bool
    {
        $result = true;

        foreach($this->pools as $pool) {
            if(!$pool->commit()) {
                $result = false;
            }
        }

        return $result;
    }

    private function addPool(CacheItemPoolInterface $pool)
    {
        array_push($this->pools, $pool);
    }
 }