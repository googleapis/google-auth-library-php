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

namespace Google\Auth\Credentials\Tests;

use Google\Auth\Credentials\CredentialsTrait;
use LogicException;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * @internal
 * @covers \Google\Auth\Credentials\CredentialsTrait
 */
class CredentialsTraitTest extends TestCase
{
    private $mockCacheItem;
    private $mockCache;

    public function setUp(): void
    {
        $this->mockCacheItem = $this->prophesize(CacheItemInterface::class);
        $this->mockCache = $this->prophesize(CacheItemPoolInterface::class);
    }

    public function testSuccessfullyPullsFromCache()
    {
        $expectedValue = ['1234'];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($expectedValue)
        ;
        $this->mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal())
        ;

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);

        $cachedValue = $implementation->gCachedToken();
        $this->assertEquals($expectedValue, $cachedValue);
    }

    public function testSuccessfullyPullsFromCacheWithInvalidKey()
    {
        $key = 'this-key-has-@-illegal-characters';
        $expectedKey = 'thiskeyhasillegalcharacters';
        $expectedValue = ['1234'];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($expectedValue)
        ;
        $this->mockCache->getItem($expectedKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal())
        ;

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
            'key' => $key,
        ]);

        $cachedValue = $implementation->gCachedToken();
        $this->assertEquals($expectedValue, $cachedValue);
    }

    public function testSuccessfullyPullsFromCacheWithLongKey()
    {
        $key = 'this-key-is-over-64-characters-and-it-will-still-work'
            . '-but-it-will-be-hashed-and-shortened';
        $expectedKey = str_replace('-', '', $key);
        $expectedKey = substr(hash('sha256', $expectedKey), 0, 64);
        $expectedValue = ['1234'];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($expectedValue)
        ;
        $this->mockCache->getItem($expectedKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal())
        ;

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
            'key' => $key,
        ]);

        $cachedValue = $implementation->gCachedToken();
        $this->assertEquals($expectedValue, $cachedValue);
    }

    public function testFailsPullFromCacheWithNoCache()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Cache has not been initialized');
        $implementation = new CredentialsTraitImplementation([
            'cache' => null,
        ]);
        $cachedValue = $implementation->gCachedToken();
    }

    public function testSuccessfullySetsToCache()
    {
        $value = ['1234'];
        $this->mockCacheItem->set($value)
            ->shouldBeCalled()
        ;
        $this->mockCacheItem->expiresAfter(Argument::any())
            ->shouldBeCalled()
        ;
        $this->mockCache->getItem('key')
            ->willReturn($this->mockCacheItem->reveal())
        ;
        $this->mockCache->save(Argument::type(CacheItemInterface::class))
            ->shouldBeCalled()
            ->willReturn(true)
        ;

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);

        $implementation->sCachedToken($value);
    }

    public function testCacheSetsExpiresAtWhenTokenExpiresAtIsSet()
    {
        $token = '2/abcdef1234567890';
        $expiresAt = time() + 10;
        $nextToken = [
            'access_token' => $token,
            'expires_at' => $expiresAt,
        ];

        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(false)
        ;
        $this->mockCacheItem->set($nextToken)
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $this->mockCacheItem->expiresAt(
            \DateTime::createFromFormat('U', (string) $expiresAt)
        )
            ->shouldBeCalledTimes(1)
        ;
        $this->mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockCacheItem->reveal())
        ;
        $this->mockCache->save(Argument::type(CacheItemInterface::class))
            ->shouldBeCalled()
            ->willReturn(true)
        ;

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);
        $implementation->setNextToken($nextToken);

        // First time, caches a token with bad expiration
        $accessToken = $implementation->fetchAuthToken();

        $this->assertEquals($nextToken, $accessToken);
    }

    public function testCacheSetsExpiresAfterWhenTokenExpiresInIsSet()
    {
        $token = '2/abcdef1234567890';
        $nextToken = [
            'access_token' => $token,
            'expires_in' => 123,
        ];

        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(false)
        ;
        $this->mockCacheItem->set($nextToken)
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $this->mockCacheItem->expiresAfter(123)
            ->shouldBeCalledTimes(1)
        ;
        $this->mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockCacheItem->reveal())
        ;
        $this->mockCache->save(Argument::type(CacheItemInterface::class))
            ->shouldBeCalled()
            ->willReturn(true)
        ;

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);
        $implementation->setNextToken($nextToken);

        // First time, caches a token with bad expiration
        $accessToken = $implementation->fetchAuthToken();

        $this->assertEquals($nextToken, $accessToken);
    }

    public function testFailsSetToCacheWithNoCache()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Cache has not been initialized');

        $implementation = new CredentialsTraitImplementation([
            'cache' => null,
        ]);
        $implementation->sCachedToken(['1234']);
    }

    public function testFailsSetToCacheWithoutKey()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Cache key cannot be empty');

        $this->mockCache->getItem(Argument::any())
            ->shouldNotBeCalled()
        ;

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
            'key' => '',
        ]);

        $cachedValue = $implementation->sCachedToken(['1234']);
        $this->assertNull($cachedValue);
    }

    public function testShouldSaveValueInCacheWithCacheLifetime()
    {
        $token = '2/abcdef1234567890';
        $nextToken = [
            'access_token' => $token,
            // no expires_in or expires_at
        ];

        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(false)
        ;
        $this->mockCacheItem->set($nextToken)
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $this->mockCacheItem->expiresAfter(123)
            ->shouldBeCalledTimes(1)
        ;
        $this->mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockCacheItem->reveal())
        ;
        $this->mockCache->save(Argument::type(CacheItemInterface::class))
            ->shouldBeCalled()
            ->willReturn(true)
        ;

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
            'cacheLifetime' => 123,
        ]);
        $implementation->setNextToken($nextToken);

        $accessToken = $implementation->fetchAuthToken();
        $this->assertEquals($nextToken, $accessToken);
    }
}

class CredentialsTraitImplementation
{
    use CredentialsTrait;

    private $key;
    private $token;

    public function __construct(array $config = [], $token = null)
    {
        $this->key = array_key_exists('key', $config) ? $config['key'] : 'key';
        $this->setCacheFromOptions($config);
        if (array_key_exists('cache', $config)) {
            // allows us to null the cache
            $this->cache = $config['cache'];
        }
    }

    // allows us to keep trait methods private
    public function gCachedToken()
    {
        return $this->getCachedToken($this->key);
    }

    public function sCachedToken($v)
    {
        $this->setCachedToken($this->key, $v);

        return true;
    }

    public function setNextToken($token)
    {
        $this->token = $token;
    }

    private function fetchAuthTokenNoCache(): array
    {
        return $this->token;
    }

    private function getCacheKey(): string
    {
        return $this->key;
    }
}
