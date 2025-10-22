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
use Psr\Cache\InvalidArgumentException;
use Symfony\Component\Filesystem\Filesystem;

class FileSystemCacheItemPoolTest extends TestCase
{
    private string $cachePath;
    private Filesystem $filesystem;
    private FileSystemCacheItemPool $pool;
    private array $invalidChars = [
        '`', '~', '!', '@', '#', '$',
        '%', '^', '&', '*', '(', ')',
        '-', '=', '+', '[', ']', '{',
        '}', '\\', ';', '\'', '"', '<',
        '>', ',', '/', ' ',
    ];

    public function setUp(): void
    {
        $this->cachePath = sys_get_temp_dir() . '/google_auth_php_test/';
        $this->filesystem = new Filesystem();
        $this->filesystem->remove($this->cachePath);
        $this->pool = new FileSystemCacheItemPool($this->cachePath);
    }

    public function tearDown(): void
    {
        $this->filesystem->remove($this->cachePath);
    }

    public function testInstanceCreatesCacheFolder()
    {
        $this->assertTrue(file_exists($this->cachePath));
        $this->assertTrue(is_dir($this->cachePath));
    }

    public function testSaveAndGetItem()
    {
        $item = $this->getNewItem();
        $item->expiresAfter(60);
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
            $this->getNewItem('NewItem2'),
            $this->getNewItem('NewItem3')
        ];

        foreach ($items as $item) {
            $this->pool->save($item);
        }

        $itemKeys = array_map(fn ($item) => $item->getKey(), $items);

        $result = $this->pool->deleteItems($itemKeys);
        $this->assertTrue($result);
    }

    public function testGetItems()
    {
        $items = [
            $this->getNewItem(),
            $this->getNewItem('NewItem2'),
            $this->getNewItem('NewItem3')
        ];

        foreach ($items as $item) {
            $this->pool->save($item);
        }

        $keys = array_map(fn ($item) => $item->getKey(), $items);
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
        $this->assertLessThan(scandir($this->cachePath), 2);
        $this->pool->clear();
        // Clear removes all the files, but scandir returns `.` and `..` as files
        $this->assertEquals(count(scandir($this->cachePath)), 2);
    }

    public function testSaveDeferredAndCommit()
    {
        $item = $this->getNewItem();
        $this->pool->saveDeferred($item);
        $this->assertFalse($this->pool->getItem($item->getKey())->isHit());

        $this->pool->commit();
        $this->assertTrue($this->pool->getItem($item->getKey())->isHit());
    }

    /**
     * @runInSeparateProcess
     */
    public function testRaceCondition()
    {
        for ($i = 0; $i < 100; $i++) {
            $cachePath = $this->cachePath . '/google_auth_php_test-' . rand();
            if (!function_exists('pcntl_fork')) {
                $this->markTestSkipped('pcntl_fork is not available');
            }

            $pids = [];
            for ($j = 0; $j < 4; $j++) {
                $pid = pcntl_fork();
                if ($pid == -1) {
                    $this->fail('Could not fork');
                }
                $pool = new FileSystemCacheItemPool($cachePath);
                $item = $pool->getItem('foo');
                $item->set('bar');
                $pool->save($item);

                if ($pid) {
                    // parent
                    $pids[] = $pid;
                } else {
                    // child
                    exit(0);
                }
            }

            // parent
            $pool->save($item);

            foreach ($pids as $pid) {
                pcntl_waitpid($pid, $status);
                $this->assertEquals(0, $status);
            }

            $this->assertTrue($pool->hasItem('foo'));
            $cachedItem = $pool->getItem('foo');
            $this->assertEquals('bar', $cachedItem->get());
        }
        $this->filesystem->remove($this->cachePath);
    }

    /**
    * @dataProvider provideInvalidChars
    */
    public function testGetItemWithIncorrectKeyShouldThrowAnException($char)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("The key '$char' is not valid. The key should follow the pattern |^[a-zA-Z0-9_\.! ]+$|");
        $item = $this->getNewItem($char);
        $this->pool->getItem($item->getKey());
    }

    /**
    * @dataProvider provideInvalidChars
    */
    public function testGetItemsWithIncorrectKeyShouldThrowAnException($char)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("The key '$char' is not valid. The key should follow the pattern |^[a-zA-Z0-9_\.! ]+$|");
        $item = $this->getNewItem($char);
        $this->pool->getItems([$item->getKey()]);
    }

    /**
    * @dataProvider provideInvalidChars
    */
    public function testHasItemWithIncorrectKeyShouldThrowAnException($char)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("The key '$char' is not valid. The key should follow the pattern |^[a-zA-Z0-9_\.! ]+$|");
        $item = $this->getNewItem($char);
        $this->pool->hasItem($item->getKey());
    }

    /**
     * @dataProvider provideInvalidChars
     */
    public function testDeleteItemWithIncorrectKeyShouldThrowAnException($char)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("The key '$char' is not valid. The key should follow the pattern |^[a-zA-Z0-9_\.! ]+$|");
        $item = $this->getNewItem($char);
        $this->pool->deleteItem($item->getKey());
    }

    /**
    * @dataProvider provideInvalidChars
    */
    public function testDeleteItemsWithIncorrectKeyShouldThrowAnException($char)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("The key '$char' is not valid. The key should follow the pattern |^[a-zA-Z0-9_\.! ]+$|");
        $item = $this->getNewItem($char);
        $this->pool->deleteItems([$item->getKey()]);
    }

    private function getNewItem(null|string $key = null): TypedItem
    {
        $item = new TypedItem($key ?? 'NewItem');
        $item->set('NewValue');

        return $item;
    }

    public function provideInvalidChars(): array
    {
        return array_map(fn ($char) => [$char], $this->invalidChars);
    }
}
