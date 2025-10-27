<?php
/*
 * Copyright 2025 Google Inc.
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
use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Auth\Cache\SysVCacheItemPool;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Filesystem\Filesystem;

class RaceConditionTest extends TestCase
{
    private static string $cachePath;
    private static Filesystem $filesystem;

    public static function setUpBeforeClass(): void
    {
        self::$cachePath = sys_get_temp_dir() . '/google_auth_php_test/';
        self::$filesystem = new Filesystem();
        self::$filesystem->remove(self::$cachePath);
    }

    /**
     * @runInSeparateProcess
     * @dataProvider provideRaceCondition
     */
    public function testRaceCondition(string $cacheClass)
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl_fork is not available');
        }
        for ($i = 0; $i < 100; $i++) {

            $pids = [];
            for ($j = 0; $j < 4; $j++) {
                $pid = pcntl_fork();
                if ($pid == -1) {
                    $this->fail('Could not fork');
                }
                $pool = $this->createCacheItemPool($cacheClass);
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
    }

    public function createCacheItemPool(string $cacheClass): CacheItemPoolInterface
    {
        switch ($cacheClass) {
            case FileSystemCacheItemPool::class:
                $cachePath = self::$cachePath . '/google_auth_php_test-' . rand();
                return new FileSystemCacheItemPool($cachePath);
            case MemoryCacheItemPool::class:
                return new MemoryCacheItemPool();
            case SysVCacheItemPool::class:
                return new SysVCacheItemPool();
        }

        throw new \Exception('Unrecognized cache class: ' . $cacheClass);
    }

    public function provideRaceCondition()
    {
        return [
            [FileSystemCacheItemPool::class],
            [MemoryCacheItemPool::class],
            [SysVCacheItemPool::class],
        ];
    }

    public static function tearDownAfterClass(): void
    {
        // remove all files generated from the filecaches
        self::$filesystem->remove(self::$cachePath);
    }
}
