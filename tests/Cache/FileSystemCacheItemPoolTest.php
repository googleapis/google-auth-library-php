<?php
/*
 * Copyright 2024 Google Inc.
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

namespace Google\Auth\Tests\Cache;

use Google\Auth\Cache\FileSystemCacheItemPool;
use Google\Auth\Cache\TypedItem;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;

class FileSystemCacheItemPoolTest extends TestCase
{
    private string $defaultCacheDirectory = 'cache/';
    private FileSystemCacheItemPool $pool;

    public function setUp(): void
    {
        $this->pool = new FileSystemCacheItemPool();
    }

    public function tearDown(): void
    {
        $files = scandir($this->defaultCacheDirectory);

        foreach($files as $fileName) {
            if ($fileName === '.' || $fileName === '..') {
                continue;
            }

            unlink($this->defaultCacheDirectory . "/" . $fileName);
        }

        rmdir($this->defaultCacheDirectory);
    }

    public function testInstanceCreatesCacheFolder()
    {
        $this->assertTrue(file_exists($this->defaultCacheDirectory));
        $this->assertTrue(is_dir($this->defaultCacheDirectory));
    }

    public function testSaveAndGetItem()
    {
        $item = $this->getNewItem();
        $this->pool->save($item);
        $retrievedItem = $this->pool->getItem($item->getKey());

        $this->assertTrue($retrievedItem->isHit());
        $this->assertEquals($retrievedItem->get(), $item->get());
    }

    public function testHasItem()
    {
        $item = $this->getNewItem();
        $this->assertFalse($this->pool->hasItem($item->getKey()));
        $this->pool->save($item);
        $this->assertTrue($this->pool->hasItem($item->getKey()));
    }

    public function testDeleteItem()
    {
        $item = $this->getNewItem();
        $this->pool->save($item);

        $this->assertTrue($this->pool->deleteItem($item->getKey()));
        $this->assertFalse($this->pool->hasItem($item->getKey()));
    }

    public function testDeleteItems()
    {
        $items = [
            $this->getNewItem(),
            $this->getNewItem("NewItem2"),
            $this->getNewItem("NewItem3")
        ];

        foreach ($items as $item) {
            $this->pool->save($item);
        }

        $result = $this->pool->deleteItems(array_map(function(CacheItemInterface $item) {
            return $item->getKey();
        }, $items));
        $this->assertTrue($result);

        $result = $this->pool->deleteItems(array_map(function(CacheItemInterface $item) {
            return $item->getKey();
        }, $items));
        $this->assertFalse($result);
    }

    public function testGetItems()
    {
        $items = [
            $this->getNewItem(),
            $this->getNewItem("NewItem2"),
            $this->getNewItem("NewItem3")
        ];

        foreach ($items as $item) {
            $this->pool->save($item);
        }

        $keys = array_map(function(CacheItemInterface $item) {
            return $item->getKey();
        }, $items);
        array_push($keys, 'NonExistant');

        $retrievedItems = $this->pool->getItems($keys);

        foreach ($items as $item) {
            $this->assertTrue($retrievedItems[$item->getKey()]->isHit());
        }

        $this->assertFalse($retrievedItems['NonExistant']->isHit());
    }

    public function testClear()
    {
        $item = $this->getNewItem();
        $this->pool->save($item);
        $this->assertLessThan(scandir($this->defaultCacheDirectory), 2);
        $this->pool->clear();
        // Clear removes all the files, but scandir returns `.` and `..` as files
        $this->assertEquals(count(scandir($this->defaultCacheDirectory)), 2);
    }

    public function testSaveDeferredAndCommit()
    {
        $item = $this->getNewItem();
        $this->pool->saveDeferred($item);
        $this->assertFalse($this->pool->getItem($item->getKey())->isHit());

        $this->pool->commit();
        $this->assertTrue($this->pool->getItem($item->getKey())->isHit());
    }

    private function getNewItem(null|string $key = null): TypedItem
    {
        $item = new TypedItem($key ?? 'NewItem');
        $item->set('NewValue');

        return $item;
    }
}