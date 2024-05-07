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

use ErrorException;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\CacheItemInterface;

class FileSystemCacheItemPool implements CacheItemPoolInterface
{
    private string $cachePath = 'cache/';
    private array $deferredPool = [];

    public function __construct($options = [])
    {
        if (array_key_exists('path', $options)) {
            $this->cachePath = $options['path'];
        }

        if (is_dir($this->cachePath)) {
            return true;
        }

        if (!mkdir($this->cachePath)) {
            throw new ErrorException("Cache folde couldn't be created");
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getItem(string $key): CacheItemInterface
    {
        if (!$this->isValidKey($key)) {
            throw new InvalidArgumentException("The key '$key' is not valid. The key should follow the pattern |^[a-zA-Z0-9_\.! ]+$|");
        }

        if (!$this->hasItem($key)) {
            return new TypedItem($key);
        }

        // Could this cause any issues? Check for result first maybe?
        return unserialize(file_get_contents($this->cacheFilePath($key)));
    }

    /**
     * {@inheritdoc}
     */
    public function getItems(array $keys = []): iterable
    {
        $result = [];

        foreach ($keys as $key) {
            if ($this->isValidKey($key)){
                throw new InvalidArgumentException("The key '$key' is not valid. The key should follow the pattern |^[a-zA-Z0-9_\.! ]+$|");
            }

            $result[$key] = $this->getItem($key);
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function hasItem(string $key): bool
    {
        $itemPath = $this->cacheFilePath($key);

        if (!file_exists($itemPath)) {
            return false;
        }

        $serializedItem = file_get_contents($this->cacheFilePath($key));
        return unserialize($serializedItem)->isHit();
    }

    /**
     * {@inheritdoc}
     */
    public function clear(): bool
    {
        if (!is_dir($this->cachePath)) {
            return false;
        }

        foreach (scandir($this->cachePath) as $fileName) {
            if ($fileName === '.' || $fileName === '..') {
                continue;
            }

            // We are not worrying for folders as the cache shouldn't have 
            // folders inside. Should we continue deleting files on false?
            if (!unlink("$this->cachePath/$fileName")) {
                return false;
            }
        }

        if (!rmdir($this->cachePath)) {
            return false;
        }
        
        if (!mkdir($this->cachePath)) {
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function deleteItem(string $key): bool
    {
        if ($this->isValidKey($key)) {
            throw new InvalidArgumentException("The key '$key' is not valid. The key should follow the pattern |^[a-zA-Z0-9_\.! ]+$|");
        }

        return unlink($this->cacheFilePath($key));
    }

    /**
     * {@inheritdoc}
     */
    public function deleteItems(array $keys): bool
    {
        $result = true;

        foreach ($keys as $key) {
            if (!$this->isValidKey($key)) {
                throw new InvalidArgumentException("The key '$key' is not valid. The key should follow the pattern |^[a-zA-Z0-9_\.! ]+$|");
            }

            if (!$this->deleteItem($key)) {
                $result = false;
            }
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function save(CacheItemInterface $item): bool
    {
        $serializedItem = serialize($item);

        $result = file_put_contents($this->cacheFilePath($item->getKey()), $serializedItem);

        // file_put_contents returns the number of bytes written
        // or a boolean. In theory there should never be a case
        // where is 0 bytes written but I still preffer to check
        // for a boolean
        if ($result === false) {
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function saveDeferred(CacheItemInterface $item): bool
    {
        array_push($this->deferredPool, $item);

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function commit(): bool
    {
        $result = true;
        
        foreach ($this->deferredPool as $item) {
            if (!$this->save($item)) {
                $result = false;
            }
        }

        return $result;
    }

    private function cacheFilePath($key): string
    {
        return "$this->cachePath/$key";
    }

    private function isValidKey(string $key): bool
    {
        return !preg_match('|^[a-zA-Z0-9_\.! ]+$|', $key);
    }
}
