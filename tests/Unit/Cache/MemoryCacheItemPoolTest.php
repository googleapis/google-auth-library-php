<?php
/*
 * Copyright 2016 Google Inc.
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

use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Auth\Cache\TypedItem;
use Google\Auth\Tests\BaseTest;
use Psr\Cache\InvalidArgumentException;

class MemoryCacheItemPoolTest extends BaseTest
{
    private $pool;

    public function setUp(): void
    {
        $this->pool = new MemoryCacheItemPool();
    }

    public function saveItem($key, $value)
    {
        $item = $this->pool->getItem($key);
        $item->set($value);
        $this->assertTrue($this->pool->save($item));

        return $item;
    }

    public function testGetsFreshItem()
    {
        $item = $this->pool->getItem('item');

        $this->assertInstanceOf(TypedItem::class, $item);
        $this->assertNull($item->get());
        $this->assertFalse($item->isHit());
    }

    public function testGetsExistingItem()
    {
        $key = 'item';
        $value = 'value';
        $this->saveItem($key, $value);
        $item = $this->pool->getItem($key);

        $this->assertInstanceOf(TypedItem::class, $item);
        $this->assertEquals($value, $item->get());
        $this->assertTrue($item->isHit());
    }

    public function testGetsMultipleItems()
    {
        $keys = ['item1', 'item2'];
        $items = $this->pool->getItems($keys);

        $this->assertEquals($keys, array_keys($items));
        $this->assertContainsOnlyInstancesOf(TypedItem::class, $items);
    }

    public function testHasItem()
    {
        $existsKey = 'does-exist';
        $this->saveItem($existsKey, 'value');

        $this->assertTrue($this->pool->hasItem($existsKey));
        $this->assertFalse($this->pool->hasItem('does-not-exist'));
    }

    public function testClear()
    {
        $key = 'item';
        $this->saveItem($key, 'value');

        $this->assertTrue($this->pool->hasItem($key));
        $this->assertTrue($this->pool->clear());
        $this->assertFalse($this->pool->hasItem($key));
    }

    public function testDeletesItem()
    {
        $key = 'item';
        $this->saveItem($key, 'value');

        $this->assertTrue($this->pool->deleteItem($key));
        $this->assertFalse($this->pool->hasItem($key));
    }

    public function testDeletesItems()
    {
        $keys = ['item1', 'item2'];

        foreach ($keys as $key) {
            $this->saveItem($key, 'value');
        }

        $this->assertTrue($this->pool->deleteItems($keys));
        $this->assertFalse($this->pool->hasItem($keys[0]));
        $this->assertFalse($this->pool->hasItem($keys[1]));
    }

    public function testDoesNotDeleteItemsWithInvalidKey()
    {
        $keys = ['item1', '{item2}', 'item3'];
        $value = 'value';
        $this->saveItem($keys[0], $value);
        $this->saveItem($keys[2], $value);

        try {
            $this->pool->deleteItems($keys);
        } catch (InvalidArgumentException $ex) {
            // continue execution
        }

        $this->assertTrue($this->pool->hasItem($keys[0]));
        $this->assertTrue($this->pool->hasItem($keys[2]));
    }

    public function testSavesItem()
    {
        $key = 'item';
        $this->saveItem($key, 'value');

        $this->assertTrue($this->pool->hasItem($key));
    }

    public function testSavesDeferredItem()
    {
        $item = $this->pool->getItem('item');
        $this->assertTrue($this->pool->saveDeferred($item));
    }

    public function testCommitsDeferredItems()
    {
        $keys = ['item1', 'item2'];

        foreach ($keys as $key) {
            $item = $this->pool->getItem($key);
            $item->set('value');
            $this->pool->saveDeferred($item);
        }

        $this->assertTrue($this->pool->commit());
        $this->assertTrue($this->pool->hasItem($keys[0]));
        $this->assertTrue($this->pool->hasItem($keys[1]));
    }

    /**
     * @dataProvider invalidKeys
     */
    public function testCheckInvalidKeysOnGetItem($key)
    {
        $this->expectException(InvalidArgumentException::class);

        $this->pool->getItem($key);
    }

    /**
     * @dataProvider invalidKeys
     */
    public function testCheckInvalidKeysOnGetItems($key)
    {
        $this->expectException(InvalidArgumentException::class);

        $this->pool->getItems([$key]);
    }

    /**
     * @dataProvider invalidKeys
     */
    public function testCheckInvalidKeysOnHasItem($key)
    {
        $this->expectException(InvalidArgumentException::class);

        $this->pool->hasItem($key);
    }

    /**
     * @dataProvider invalidKeys
     */
    public function testCheckInvalidKeysOnDeleteItem($key)
    {
        $this->expectException(InvalidArgumentException::class);

        $this->pool->deleteItem($key);
    }

    /**
     * @dataProvider invalidKeys
     */
    public function testCheckInvalidKeysOnDeleteItems($key)
    {
        $this->expectException(InvalidArgumentException::class);

        $this->pool->deleteItems([$key]);
    }

    public function invalidKeys()
    {
        return [
            [1],
            [true],
            [null],
            [new \DateTime()],
            ['{'],
            ['}'],
            ['('],
            [')'],
            ['/'],
            ['\\'],
            ['@'],
            [':'],
            [[]]
        ];
    }
}
