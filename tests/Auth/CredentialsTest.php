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

use Google\Auth\Credentials\ComputeCredentials;
use Google\Auth\Credentials\CredentialsInterface;
use Google\Auth\Credentials\OAuth2Credentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountJwtAccessCredentials;
use Google\Auth\Credentials\UserRefreshCredentials;
use Google\Auth\OAuth2;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * @internal
 * @covers \Google\Auth\Credentials\ComputeCredentials
 * @covers \Google\Auth\Credentials\CredentialsInterface
 * @covers \Google\Auth\Credentials\OAuth2Credentials
 * @covers \Google\Auth\Credentials\ServiceAccountCredentials
 * @covers \Google\Auth\Credentials\ServiceAccountJwtAccessCredentials
 * @covers \Google\Auth\Credentials\UserRefreshCredentials
 */
class CredentialsTest extends TestCase
{
    private $serviceAccountCreds = [
        'client_email' => 'fakeclientemail',
        'private_key' => 'fakeprivatekey',
    ];
    private $userRefreshCreds = [
        'client_id' => 'fakeclientid',
        'client_secret' => 'fakeclientsecret',
        'refresh_token' => 'fakerefreshtoken',
    ];

    public function provideIdTokenCredentials()
    {
        return [
            [ComputeCredentials::class],
            [ServiceAccountCredentials::class, $this->serviceAccountCreds],
        ];
    }

    public function provideAccessTokenCredentials()
    {
        return [
            [ComputeCredentials::class],
            [OAuth2Credentials::class, new OAuth2()],
            [ServiceAccountCredentials::class, $this->serviceAccountCreds],
            [
                ServiceAccountJwtAccessCredentials::class,
                $this->serviceAccountCreds,
                ['audience' => 'foo'],
            ],
            [UserRefreshCredentials::class, $this->userRefreshCreds],
        ];
    }

    public function provideGetRequestMetadataCredentials()
    {
        return [
            [ComputeCredentials::class],
            [OAuth2Credentials::class, new OAuth2()],
            [
                ServiceAccountCredentials::class,
                $this->serviceAccountCreds,
                ['scope' => '123'],
            ],
            [
                ServiceAccountJwtAccessCredentials::class,
                $this->serviceAccountCreds,
                ['audience' => 'foo'],
                'http://authuri/',
            ],
            [UserRefreshCredentials::class, $this->userRefreshCreds],
        ];
    }

    /**
     * @dataProvider provideAccessTokenCredentials
     *
     * @param null|mixed $firstArgument
     */
    public function testUsesCachedAccessToken(
        string $credentialsClass,
        $firstArgument = null,
        array $options = []
    ) {
        $cachedValue = ['access_token' => '2/abcdef1234567890'];
        $mockCacheItem = $this->prophesize(CacheItemInterface::class);
        $mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue)
        ;
        $mockCache = $this->prophesize(CacheItemPoolInterface::class);
        $mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(1)
            ->willReturn($mockCacheItem->reveal())
        ;

        $options['cache'] = $mockCache->reveal();

        // Run the test.
        $credentials = $this->createCredentials(
            $credentialsClass,
            $firstArgument,
            $options
        );

        $accessToken = $credentials->fetchAuthToken();
        $this->assertEquals($accessToken, $cachedValue);
    }

    /**
     * @dataProvider provideIdTokenCredentials
     *
     * @param null|mixed $firstArgument
     */
    public function testUsesCachedIdToken(
        string $credentialsClass,
        $firstArgument = null,
        array $options = []
    ) {
        // Fetch an access token first
        $cacheKey = null;
        $cachedValue = ['access_token' => '2/abcdef1234567890'];
        $phpunit = $this;
        $mockCacheItem = $this->prophesize(CacheItemInterface::class);
        $mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue)
        ;
        $mockCache = $this->prophesize(CacheItemPoolInterface::class);
        $mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(1)
            ->will(function ($args) use (&$cacheKey, $mockCacheItem) {
                $cacheKey = $args[0]; // save the cache key

                return $mockCacheItem->reveal();
            })
        ;

        $options['cache'] = $mockCache->reveal();

        $credentials = $this->createCredentials(
            $credentialsClass,
            $firstArgument,
            $options
        );
        $accessToken = $credentials->fetchAuthToken();

        // Now fetch an ID token
        $cachedValue = ['id_token' => '2/abcdef1234567890'];
        $mockCacheItem = $this->prophesize(CacheItemInterface::class);
        $mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue)
        ;
        $mockCache = $this->prophesize(CacheItemPoolInterface::class);
        $mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(1)
            ->will(function ($args) use ($phpunit, $cacheKey, $mockCacheItem) {
                // Assert the cache key is different for ID tokens
                $phpunit->assertNotEquals($cacheKey, $args[0]);

                return $mockCacheItem->reveal();
            })
        ;

        $targetAudience = 'a-target-audience';
        $options['targetAudience'] = $targetAudience;
        $options['cache'] = $mockCache->reveal();
        $credentials = $this->createCredentials(
            $credentialsClass,
            $firstArgument,
            $options
        );

        $idToken = $credentials->fetchAuthToken();
        $this->assertEquals($idToken, $cachedValue);
    }

    /**
     * @dataProvider provideGetRequestMetadataCredentials
     *
     * @param null|mixed $firstArgument
     */
    public function testGetRequestMetadataWithCache(
        string $credentialsClass,
        $firstArgument = null,
        array $options = [],
        string $authUri = null
    ) {
        $token = '2/abcdef1234567890';
        $cachedValue = ['access_token' => $token];
        $mockCacheItem = $this->prophesize(CacheItemInterface::class);
        $mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue)
        ;
        $mockCache = $this->prophesize(CacheItemPoolInterface::class);
        $mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(1)
            ->willReturn($mockCacheItem->reveal())
        ;

        $options['cache'] = $mockCache->reveal();

        $credentials = $this->createCredentials(
            $credentialsClass,
            $firstArgument,
            $options
        );

        $metadata = $credentials->getRequestMetadata($authUri);

        $this->assertArrayHasKey('Authorization', $metadata);
        $this->assertEquals("Bearer {$token}", $metadata['Authorization']);
    }

    /**
     * @dataProvider provideAccessTokenCredentials
     *
     * @param null|mixed $firstArgument
     */
    public function testShouldReturnValueWhenNotExpired(
        string $credentialsClass,
        $firstArgument = null,
        array $options = []
    ) {
        $token = '2/abcdef1234567890';
        $expiresAt = time() + 10;
        $cachedValue = [
            'access_token' => $token,
            'expires_at' => $expiresAt,
        ];
        $mockCacheItem = $this->prophesize(CacheItemInterface::class);
        $mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue)
        ;
        $mockCache = $this->prophesize(CacheItemPoolInterface::class);
        $mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(1)
            ->willReturn($mockCacheItem->reveal())
        ;

        // Run the test.
        $options['cache'] = $mockCache->reveal();
        $credentials = $this->createCredentials(
            $credentialsClass,
            $firstArgument,
            $options
        );

        $accessToken = $credentials->fetchAuthToken();
        $this->assertEquals($accessToken, [
            'access_token' => $token,
            'expires_at' => $expiresAt,
        ]);
    }

    /**
     * @dataProvider provideAccessTokenCredentials
     *
     * @param null|mixed $firstArgument
     */
    public function testShouldSaveValueInCacheWithCachePrefix(
        string $credentialsClass,
        $firstArgument = null,
        array $options = []
    ) {
        $phpunit = $this;
        $prefix = 'mycacheprefix';
        $cachedValue = [
            'access_token' => '2/abcdef1234567890',
            'expires_at' => time() + 10,
        ];
        $mockCacheItem = $this->prophesize(CacheItemInterface::class);
        $mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true)
        ;
        $mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue)
        ;
        $mockCache = $this->prophesize(CacheItemPoolInterface::class);
        $mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(1)
            ->will(function ($args) use ($phpunit, $prefix, $mockCacheItem) {
                $cacheKey = $args[0];
                $phpunit->assertStringStartsWith($prefix, $cacheKey);

                return $mockCacheItem->reveal();
            })
        ;

        // Run the test.
        $options['cache'] = $mockCache->reveal();
        $options['cachePrefix'] = $prefix;
        $credentials = $this->createCredentials(
            $credentialsClass,
            $firstArgument,
            $options
        );

        $accessToken = $credentials->fetchAuthToken();
        $this->assertEquals($cachedValue, $accessToken);
    }

    private function createCredentials(
        string $credentialsClass,
        $firstArgument,
        array $options
    ): CredentialsInterface {
        if ($firstArgument) {
            return new $credentialsClass($firstArgument, $options);
        }

        return new $credentialsClass($options);
    }
}
