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
        for ($i = 0; $i < 50; $i++) {
            // SysV Cache warmup to prevent segment creation race
            if ($cacheClass === SysVCacheItemPool::class) {
                $warmupPool = $this->createCacheItemPool($cacheClass, $i);
                $warmupItem = $warmupPool->getItem('warmup');
                $warmupItem->set('ok');
                $warmupPool->save($warmupItem);
                unset($warmupPool);
            }

            $pids = [];
            for ($j = 0; $j < 4; $j++) {
                $pid = pcntl_fork();
                if ($pid == -1) {
                    $this->fail('Could not fork');
                }

                // Always create a new pool instance inside the loop (matches original)
                $pool = $this->createCacheItemPool($cacheClass, $i);
                $item = $pool->getItem('foo');
                $item->set('bar');
                $this->assertTrue($pool->save($item));

                if ($pid) {
                    // parent
                    $pids[] = $pid;
                    if ($cacheClass === SysVCacheItemPool::class) {
                        // For SysV, we must destroy the parent's pool object immediately
                        // so it is not inherited by the next child process.
                        unset($pool);
                    }
                } else {
                    // child
                    exit(0);
                }
            }

            // parent final save (matching original test logic)
            // Note: for SysV, $pool was unset inside the loop, so we must recreate it.
            // For FileSystem/Memory, $pool is still the one from the last iteration ($j=3).
            if ($cacheClass === SysVCacheItemPool::class) {
                $pool = $this->createCacheItemPool($cacheClass, $i);
                // We need to re-get the item for this new pool
                $item = $pool->getItem('foo');
                $item->set('bar');
            }
            $this->assertTrue($pool->save($item));

            foreach ($pids as $pid) {
                pcntl_waitpid($pid, $status);
                $this->assertEquals(0, $status);
            }

            $this->assertTrue($pool->hasItem('foo'));
            $cachedItem = $pool->getItem('foo');
            $this->assertEquals('bar', $cachedItem->get());

            $pool->clear();
            unset($pool);
        }
    }

    public function createCacheItemPool(string $cacheClass, int $iteration = 0): CacheItemPoolInterface
    {
        switch ($cacheClass) {
            case FileSystemCacheItemPool::class:
                $cachePath = self::$cachePath . '/google_auth_php_test-' . rand();
                return new FileSystemCacheItemPool($cachePath);
            case MemoryCacheItemPool::class:
                return new MemoryCacheItemPool();
            case SysVCacheItemPool::class:
                return new SysVCacheItemPool([
                    'proj' => chr(65 + ($iteration % 26)),
                    'semProj' => chr(97 + ($iteration % 26))
                ]);
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
