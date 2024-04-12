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

namespace Google\Auth\Tests;

use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Auth\Credentials\GCECredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\CredentialsLoader;
use Google\Auth\FetchAuthTokenCache;
use Google\Auth\FetchAuthTokenInterface;
use Google\Auth\GetUniverseDomainInterface;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;
use RuntimeException;

class FetchAuthTokenCacheTest extends BaseTest
{
    use ProphecyTrait;

    private $mockFetcher;
    private $mockCacheItem;
    private $mockCache;
    private $mockSigner;
    private static string $cacheKey;

    protected function setUp(): void
    {
        $this->mockFetcher = $this->prophesize();
        $this->mockFetcher->willImplement('Google\Auth\FetchAuthTokenInterface');
        $this->mockFetcher->willImplement('Google\Auth\UpdateMetadataInterface');
        $this->mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $this->mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $this->mockSigner = $this->prophesize('Google\Auth\SignBlobInterface');
    }

    public function testUsesCachedAccessToken()
    {
        $cacheKey = 'myKey';
        $token = '2/abcdef1234567890';
        $cachedValue = ['access_token' => $token];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCache->getItem($cacheKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockFetcher->fetchAuthToken()
            ->shouldNotBeCalled();
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $accessToken = $cachedFetcher->fetchAuthToken();
        $this->assertEquals($accessToken, ['access_token' => $token]);
    }

    public function testUsesCachedIdToken()
    {
        $cacheKey = 'myKey';
        $token = '2/abcdef1234567890';
        $cachedValue = ['id_token' => $token];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCache->getItem($cacheKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockFetcher->fetchAuthToken()
            ->shouldNotBeCalled();
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $idToken = $cachedFetcher->fetchAuthToken();
        $this->assertEquals($idToken, ['id_token' => $token]);
    }

    public function testUpdateMetadataWithCache()
    {
        $cacheKey = 'myKey';
        $token = '2/abcdef1234567890';
        $cachedValue = ['access_token' => $token];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCache->getItem($cacheKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockFetcher->fetchAuthToken()
            ->shouldNotBeCalled();
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);
        $this->mockFetcher->updateMetadata(Argument::type('array'), null, null)
            ->shouldBeCalled()
            ->will(function ($args, $fetcher) {
                return $args[0];
            });

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $headers = $cachedFetcher->updateMetadata(['foo' => 'bar']);
        $this->assertArrayHasKey('authorization', $headers);
        $this->assertEquals(["Bearer $token"], $headers['authorization']);
        $this->assertArrayHasKey('foo', $headers);
        $this->assertEquals('bar', $headers['foo']);
    }

    public function testUpdateMetadataWithoutCache()
    {
        $cacheKey = 'myKey';
        $token = '2/abcdef1234567890';
        $value = ['access_token' => $token];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(false);
        $this->mockCache->getItem($cacheKey)
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);
        $this->mockFetcher->getLastReceivedToken()
            ->shouldBeCalled()
            ->willReturn($value);
        $this->mockCacheItem->set($value)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCacheItem->expiresAfter(1500)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save($this->mockCacheItem)
            ->shouldBeCalledTimes(1);
        $this->mockFetcher->updateMetadata(Argument::type('array'), null, null)
            ->shouldBeCalled()
            ->will(function ($args, $fetcher) use ($token) {
                $args[0]['authorization'] = ["Bearer $token"];
                return $args[0];
            });

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $headers = $cachedFetcher->updateMetadata(['foo' => 'bar']);
        $this->assertArrayHasKey('authorization', $headers);
        $this->assertEquals(["Bearer $token"], $headers['authorization']);
        $this->assertArrayHasKey('foo', $headers);
        $this->assertEquals('bar', $headers['foo']);
    }

    public function testUpdateMetadataWithJwtAccess()
    {
        $privateKey =  file_get_contents(__DIR__ . '/fixtures/private.pem');
        $testJson = [
            'private_key' => $privateKey,
            'private_key_id' => 'key123',
            'client_email' => 'test@example.com',
            'client_id' => 'client123',
            'type' => 'service_account',
            'project_id' => 'example_project',
        ];

        $fetcher = new ServiceAccountCredentials(null, $testJson);
        $cache = new MemoryCacheItemPool();

        $cachedFetcher = new FetchAuthTokenCache(
            $fetcher,
            null,
            $cache
        );
        $metadata = $cachedFetcher->updateMetadata([], 'http://test-auth-uri');
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $metadata
        );

        $authorization = $metadata[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertTrue(is_array($authorization));

        $bearerToken = current($authorization);
        $this->assertTrue(is_string($bearerToken));
        $this->assertEquals(0, strpos($bearerToken, 'Bearer '));
        $token = str_replace('Bearer ', '', $bearerToken);

        $lastReceivedToken = $cachedFetcher->getLastReceivedToken();
        $this->assertArrayHasKey('access_token', $lastReceivedToken);
        $this->assertEquals($token, $lastReceivedToken['access_token']);

        // Ensure token is cached
        $metadata2 = $cachedFetcher->updateMetadata([], 'http://test-auth-uri');
        $this->assertEquals($metadata, $metadata2);

        // Ensure token for different URI is NOT cached
        $metadata3 = $cachedFetcher->updateMetadata([], 'http://test-auth-uri-2');
        $this->assertNotEquals($metadata, $metadata3);
    }

    public function testUpdateMetadataWithGceCredForIdToken()
    {
        $idToken = '123asdfghjkl';
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            new Response(200, [], Utils::streamFor($idToken)),
        ]);
        $fetcher = new GCECredentials(null, null, 'https://example.test.com');
        $cache = new MemoryCacheItemPool();

        $cachedFetcher = new FetchAuthTokenCache(
            $fetcher,
            null,
            $cache
        );
        $metadata = $cachedFetcher->updateMetadata(
            [],
            'http://test-auth-uri',
            $httpHandler
        );
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $metadata
        );

        $authorization = $metadata[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertTrue(is_array($authorization));

        $bearerToken = current($authorization);
        $this->assertTrue(is_string($bearerToken));
        $this->assertEquals(0, strpos($bearerToken, 'Bearer '));
        $token = str_replace('Bearer ', '', $bearerToken);

        $lastReceivedToken = $cachedFetcher->getLastReceivedToken();
        $this->assertArrayHasKey('id_token', $lastReceivedToken);
        $this->assertEquals($idToken, $lastReceivedToken['id_token']);

        // Ensure token is cached
        $metadata2 = $cachedFetcher->updateMetadata([], 'http://test-auth-uri');
        $this->assertEquals($metadata, $metadata2);

        // Ensure token for different URI is NOT cached
        $metadata3 = $cachedFetcher->updateMetadata([], 'http://test-auth-uri-2');
        $this->assertNotEquals($metadata, $metadata3);
    }

    public function testUpdateMetadataWithInvalidFetcher()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Credentials fetcher does not implement Google\Auth\UpdateMetadataInterface');

        $mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $cachedFetcher->updateMetadata(['foo' => 'bar']);
    }

    public function testShouldReturnValueWhenNotExpired()
    {
        $cacheKey = 'myKey';
        $token = '2/abcdef1234567890';
        $expiresAt = time() + 20;
        $cachedValue = [
            'access_token' => $token,
            'expires_at' => $expiresAt,
        ];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCache->getItem($cacheKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockFetcher->fetchAuthToken()
            ->shouldNotBeCalled();
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $accessToken = $cachedFetcher->fetchAuthToken();
        $this->assertEquals($accessToken, [
            'access_token' => $token,
            'expires_at' => $expiresAt
        ]);
    }

    public function testShouldNotReturnValueWhenExpired()
    {
        $cacheKey = 'myKey';
        $token = '2/abcdef1234567890';
        $expiresAt = time() - 10;
        $cachedValue = [
            'access_token' => $token,
            'expires_at' => $expiresAt,
        ];
        $newToken = ['access_token' => '3/abcdef1234567890'];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCacheItem->set($newToken)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCacheItem->expiresAfter(1500)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->getItem($cacheKey)
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockFetcher->fetchAuthToken(null)
            ->shouldBeCalledTimes(1)
            ->willReturn($newToken);
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);
        $this->mockCache->save($this->mockCacheItem)
            ->shouldBeCalledTimes(1);

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $accessToken = $cachedFetcher->fetchAuthToken();
        $this->assertEquals($newToken, $accessToken);
    }

    public function testShouldNotReturnValueWhenExpiredWithinEagerThreshold()
    {
        $cacheKey = 'myKey';
        $token = '2/abcdef1234567890';
        $expiresAt = time() + 5;
        $cachedValue = [
            'access_token' => $token,
            'expires_at' => $expiresAt,
        ];
        $newToken = ['access_token' => '3/abcdef1234567890'];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCacheItem->set($newToken)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCacheItem->expiresAfter(1500)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->getItem($cacheKey)
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockFetcher->fetchAuthToken(null)
            ->shouldBeCalledTimes(1)
            ->willReturn($newToken);
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);
        $this->mockCache->save($this->mockCacheItem)
            ->shouldBeCalledTimes(1);

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $accessToken = $cachedFetcher->fetchAuthToken();
        $this->assertEquals($newToken, $accessToken);
    }

    public function testGetsCachedAuthTokenUsingCachePrefix()
    {
        $prefix = 'test_prefix_';
        $cacheKey = 'myKey';
        $token = '2/abcdef1234567890';
        $cachedValue = ['access_token' => $token];
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCache->getItem($prefix . $cacheKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockFetcher->fetchAuthToken()
            ->shouldNotBeCalled();
        $this->mockFetcher->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);

        // Run the test
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            ['prefix' => $prefix],
            $this->mockCache->reveal()
        );
        $accessToken = $cachedFetcher->fetchAuthToken();
        $this->assertEquals($accessToken, ['access_token' => $token]);
    }

    public function testShouldSaveValueInCacheWithCacheOptions()
    {
        $prefix = 'test_prefix_';
        $lifetime = '70707';
        $cacheKey = 'myKey';
        $token = '1/abcdef1234567890';
        $cachedValue = ['access_token' => $token];
        $this->mockCacheItem->get(Argument::any())
            ->willReturn(null);
        $this->mockCacheItem->isHit()
            ->willReturn(false);
        $this->mockCacheItem->set($cachedValue)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCacheItem->expiresAfter($lifetime)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->getItem($prefix . $cacheKey)
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalled();
        $this->mockFetcher->getCacheKey()
            ->willReturn($cacheKey);
        $this->mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);

        // Run the test
        $cachedFetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            ['prefix' => $prefix, 'lifetime' => $lifetime],
            $this->mockCache->reveal()
        );
        $accessToken = $cachedFetcher->fetchAuthToken();
        $this->assertEquals($accessToken, ['access_token' => $token]);
    }

    public function testGetLastReceivedToken()
    {
        $token = 'foo';

        $mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');
        $mockFetcher->getLastReceivedToken()
            ->shouldBeCalled()
            ->willReturn([
                'access_token' => $token
            ]);

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            [],
            $this->mockCache->reveal()
        );

        $this->assertEquals($token, $fetcher->getLastReceivedToken()['access_token']);
    }

    public function testGetClientName()
    {
        $name = 'test@example.com';

        $this->mockSigner->getClientName(null)
            ->shouldBeCalled()
            ->willReturn($name);

        $fetcher = new FetchAuthTokenCache(
            $this->mockSigner->reveal(),
            [],
            $this->mockCache->reveal()
        );

        $this->assertEquals($name, $fetcher->getClientName());
    }

    public function testGetClientNameWithInvalidFetcher()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Credentials fetcher does not implement Google\Auth\SignBlobInterface');

        $mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');

        // Run the test.
        $cachedFetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            null,
            $this->mockCache->reveal()
        );
        $cachedFetcher->getClientName();
    }

    public function testSignBlob()
    {
        $stringToSign = 'foobar';
        $signature = 'helloworld';

        $this->mockSigner->willImplement('Google\Auth\FetchAuthTokenInterface');
        $this->mockSigner->signBlob($stringToSign, true)
            ->shouldBeCalled()
            ->willReturn($signature);

        $fetcher = new FetchAuthTokenCache(
            $this->mockSigner->reveal(),
            [],
            $this->mockCache->reveal()
        );

        $this->assertEquals($signature, $fetcher->signBlob($stringToSign, true));
    }

    public function testGCECredentialsSignBlob()
    {
        $stringToSign = 'foobar';
        $signature = 'helloworld';
        $cacheKey = 'myKey';
        $token = '2/abcdef1234567890';
        $cachedValue = ['access_token' => $token];

        $mockGce = $this->prophesize('Google\Auth\Credentials\GCECredentials');
        $mockGce->signBlob($stringToSign, true, $token)
            ->shouldBeCalled()
            ->willReturn($signature);

        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCache->getItem($cacheKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $mockGce->getCacheKey()
            ->shouldBeCalled()
            ->willReturn($cacheKey);

        $fetcher = new FetchAuthTokenCache(
            $mockGce->reveal(),
            [],
            $this->mockCache->reveal()
        );

        $this->assertEquals($signature, $fetcher->signBlob($stringToSign, true));
    }

    public function testSignBlobInvalidFetcher()
    {
        $this->expectException(RuntimeException::class);

        $this->mockFetcher->signBlob('test')
            ->shouldNotbeCalled();

        $fetcher = new FetchAuthTokenCache(
            $this->mockFetcher->reveal(),
            [],
            $this->mockCache
        );

        $fetcher->signBlob('test');
    }

    public function testGetProjectId()
    {
        $projectId = 'foobar';

        $mockFetcher = $this->prophesize('Google\Auth\ProjectIdProviderInterface');
        $mockFetcher->willImplement('Google\Auth\FetchAuthTokenInterface');
        $mockFetcher->getProjectId(null)
            ->shouldBeCalled()
            ->willReturn($projectId);

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            [],
            $this->mockCache->reveal()
        );

        $this->assertEquals($projectId, $fetcher->getProjectId());
    }

    public function testGetProjectIdInvalidFetcher()
    {
        $this->expectException(RuntimeException::class);

        $mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');
        $mockFetcher->getProjectId()
            ->shouldNotbeCalled();

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            [],
            $this->mockCache
        );

        $fetcher->getProjectId();
    }

    public function testGetUniverseDomain()
    {
        $universeDomain = 'foobar';

        $mockFetcher = $this->prophesize('Google\Auth\GetUniverseDomainInterface');
        $mockFetcher->willImplement('Google\Auth\FetchAuthTokenInterface');
        $mockFetcher->getUniverseDomain()
            ->shouldBeCalled()
            ->willReturn($universeDomain);

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            [],
            $this->mockCache->reveal()
        );

        $this->assertEquals($universeDomain, $fetcher->getUniverseDomain());
    }

    public function testGetUniverseDomainInvalidFetcher()
    {
        $mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface');

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            [],
            $this->mockCache->reveal()
        );

        $this->assertEquals(
            GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN,
            $fetcher->getUniverseDomain()
        );
    }

    public function testGetFetcher()
    {
        $mockFetcher = $this->prophesize('Google\Auth\FetchAuthTokenInterface')
            ->reveal();
        $fetcher = new FetchAuthTokenCache(
            $mockFetcher,
            [],
            $this->mockCache->reveal()
        );

        $this->assertSame($mockFetcher, $fetcher->getFetcher());
    }

    public function testCacheUniverseDomain()
    {
        $mockFetcher = $this->prophesize(FetchAuthTokenInterface::class);
        $mockFetcher->willImplement(GetUniverseDomainInterface::class);
        $mockFetcher->getUniverseDomain()
            ->shouldBeCalledTimes(2)
            ->willReturn('example-universe.domain');
        $mockFetcher->getCacheKey()
            ->shouldNotBeCalled();

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            ['cacheUniverseDomain' => false],
            new MemoryCacheItemPool()
        );

        // Call it twice
        $this->assertEquals('example-universe.domain', $fetcher->getUniverseDomain());
        $this->assertEquals('example-universe.domain', $fetcher->getUniverseDomain());

        // Now set  the cache option and ensure it's only called once
        $mockFetcher = $this->prophesize(FetchAuthTokenInterface::class);
        $mockFetcher->willImplement(GetUniverseDomainInterface::class);
        $mockFetcher->getUniverseDomain()
            ->shouldBeCalledOnce()
            ->willReturn('example-universe.domain');
        $mockFetcher->getCacheKey()
            ->shouldBeCalledTimes(2)
            ->willReturn('my-cache-key');

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            ['cacheUniverseDomain' => true],
            new MemoryCacheItemPool()
        );
        $this->assertEquals('example-universe.domain', $fetcher->getUniverseDomain());
        $this->assertEquals('example-universe.domain', $fetcher->getUniverseDomain());
    }

    public function testCacheUniverseDomainByDefaultForGCECredentials()
    {
        $mockFetcher = $this->prophesize(GCECredentials::class);
        $mockFetcher->getUniverseDomain()
            ->shouldBeCalledOnce()
            ->willReturn('example-universe.domain');
        $mockFetcher->getCacheKey()
            ->shouldBeCalledTimes(2)
            ->willReturn('my-cache-key');

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            [], // don't set cacheUniverseDomain, it will be true by default
            new MemoryCacheItemPool()
        );

        $this->assertEquals('example-universe.domain', $fetcher->getUniverseDomain());
        $this->assertEquals('example-universe.domain', $fetcher->getUniverseDomain());
    }

    public function testUniverseDomainWithFileCache()
    {
        require_once __DIR__ . '/mocks/TestFileCacheItemPool.php';
        self::$cacheKey = 'universe-domain-check-' . time() . rand();

        $cache = new TestFileCacheItemPool(sys_get_temp_dir() . '/google-auth-test');

        $mockFetcher = $this->prophesize(FetchAuthTokenInterface::class);
        $mockFetcher->willImplement(GetUniverseDomainInterface::class);
        $mockFetcher->getUniverseDomain()
            ->shouldBeCalledOnce()
            ->willReturn('example-universe.domain');
        $mockFetcher->getCacheKey()
            ->shouldBeCalledOnce()
            ->willReturn(self::$cacheKey);

        $fetcher = new FetchAuthTokenCache(
            $mockFetcher->reveal(),
            ['cacheUniverseDomain' => true],
            $cache
        );
        $this->assertEquals('example-universe.domain', $fetcher->getUniverseDomain());
    }

    /**
     * @depends testUniverseDomainWithFileCache
     */
    public function testUniverseDomainWithFileCacheProcess2()
    {
        $cmd = sprintf('php %s/mocks/test_file_cache_separate_process.php %s', __DIR__, self::$cacheKey);
        exec($cmd, $output, $retVar);

        $this->assertEquals(0, $retVar);
        $this->assertEquals('example-universe.domain', implode('', $output));
    }
}
