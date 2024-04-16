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

use DomainException;
use Google\Auth\ApplicationDefaultCredentials;
use Google\Auth\Credentials\ExternalAccountCredentials;
use Google\Auth\Credentials\GCECredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\CredentialsLoader;
use Google\Auth\CredentialSource;
use Google\Auth\GCECache;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use ReflectionClass;

/**
 * @runTestsInSeparateProcesses
 */
class ApplicationDefaultCredentialsTest extends TestCase
{
    use ProphecyTrait;

    private $originalHome;
    private $targetAudience = 'a target audience';
    private $quotaProject = 'a-quota-project';
    private $originalServiceAccount;

    public function testGetCredentialsFailsIfEnvSpecifiesNonExistentFile()
    {
        $this->expectException(DomainException::class);

        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        ApplicationDefaultCredentials::getCredentials('a scope');
    }

    public function testLoadsOKIfEnvSpecifiedIsValid()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $this->assertNotNull(
            ApplicationDefaultCredentials::getCredentials('a scope')
        );
    }

    public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        $this->assertNotNull(
            ApplicationDefaultCredentials::getCredentials('a scope')
        );
    }

    public function testFailsIfNotOnGceAndNoDefaultFileFound()
    {
        $this->expectException(DomainException::class);

        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            new Response(500),
            new Response(500),
            new Response(500)
        ]);

        ApplicationDefaultCredentials::getCredentials('a scope', $httpHandler);
    }

    public function testSuccedsIfNoDefaultFilesButIsOnGCE()
    {
        putenv('HOME');

        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            new Response(200, [], Utils::streamFor($jsonTokens)),
        ]);

        $this->assertInstanceOf(
            'Google\Auth\Credentials\GCECredentials',
            ApplicationDefaultCredentials::getCredentials('a scope', $httpHandler)
        );
    }

    public function testGceCredentials()
    {
        putenv('HOME');

        $jsonTokens = json_encode(['access_token' => 'abc']);

        $creds = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            $httpHandler = getHandler([
                new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
                new Response(200, [], Utils::streamFor($jsonTokens)),
            ]), // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a+default+scope' // $defaultScope
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\GCECredentials',
            $creds
        );

        $uriProperty = (new ReflectionClass($creds))->getProperty('tokenUri');
        $uriProperty->setAccessible(true);

        // used default scope
        $tokenUri = $uriProperty->getValue($creds);
        $this->assertStringContainsString('a+default+scope', $tokenUri);

        $creds = ApplicationDefaultCredentials::getCredentials(
            'a+user+scope', // $scope
            getHandler([
                new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
                new Response(200, [], Utils::streamFor($jsonTokens)),
            ]), // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a+default+scope' // $defaultScope
        );

        // did not use default scope
        $tokenUri = $uriProperty->getValue($creds);
        $this->assertStringContainsString('a+user+scope', $tokenUri);
    }

    public function testImpersonatedServiceAccountCredentials()
    {
        putenv('HOME=' . __DIR__ . '/fixtures5');
        $creds = ApplicationDefaultCredentials::getCredentials(
            null,
            null,
            null,
            null,
            null,
            'a default scope'
        );
        $this->assertInstanceOf(
            'Google\Auth\Credentials\ImpersonatedServiceAccountCredentials',
            $creds);

        $this->assertEquals('service_account_name@namespace.iam.gserviceaccount.com', $creds->getClientName());

        $sourceCredentialsProperty = (new ReflectionClass($creds))->getProperty('sourceCredentials');
        $sourceCredentialsProperty->setAccessible(true);

        // used default scope
        $sourceCredentials = $sourceCredentialsProperty->getValue($creds);
        $this->assertInstanceOf(
            'Google\Auth\Credentials\UserRefreshCredentials',
            $sourceCredentials);
    }

    public function testUserRefreshCredentials()
    {
        putenv('HOME=' . __DIR__ . '/fixtures2');

        $creds = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a default scope' // $defaultScope
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\UserRefreshCredentials',
            $creds
        );

        $authProperty = (new ReflectionClass($creds))->getProperty('auth');
        $authProperty->setAccessible(true);

        // used default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('a default scope', $auth->getScope());

        $creds = ApplicationDefaultCredentials::getCredentials(
            'a user scope', // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a default scope' // $defaultScope
        );

        // did not use default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('a user scope', $auth->getScope());
    }

    public function testServiceAccountCredentials()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');

        $creds = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a default scope' // $defaultScope
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ServiceAccountCredentials',
            $creds
        );

        $authProperty = (new ReflectionClass($creds))->getProperty('auth');
        $authProperty->setAccessible(true);

        // did not use default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('', $auth->getScope());

        $creds = ApplicationDefaultCredentials::getCredentials(
            'a user scope', // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a default scope' // $defaultScope
        );

        // used user scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('a user scope', $auth->getScope());
    }

    public function testDefaultScopeArray()
    {
        putenv('HOME=' . __DIR__ . '/fixtures2');

        $creds = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            ['onescope', 'twoscope'] // $defaultScope
        );

        $authProperty = (new ReflectionClass($creds))->getProperty('auth');
        $authProperty->setAccessible(true);

        // used default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('onescope twoscope', $auth->getScope());
    }

    public function testGetMiddlewareFailsIfEnvSpecifiesNonExistentFile()
    {
        $this->expectException(DomainException::class);

        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        ApplicationDefaultCredentials::getMiddleware('a scope');
    }

    public function testGetMiddlewareLoadsOKIfEnvSpecifiedIsValid()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $this->assertNotNull(ApplicationDefaultCredentials::getMiddleware('a scope'));
    }

    public function testLGetMiddlewareoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        $this->assertNotNull(ApplicationDefaultCredentials::getMiddleware('a scope'));
    }

    public function testGetMiddlewareFailsIfNotOnGceAndNoDefaultFileFound()
    {
        $this->expectException(DomainException::class);

        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            new Response(500),
            new Response(500),
            new Response(500)
        ]);

        ApplicationDefaultCredentials::getMiddleware('a scope', $httpHandler);
    }

    public function testGetMiddlewareWithCacheOptions()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $httpHandler = getHandler([
            new Response(200),
        ]);

        $cacheOptions = [];
        $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

        $middleware = ApplicationDefaultCredentials::getMiddleware(
            'a scope',
            $httpHandler,
            $cacheOptions,
            $cachePool->reveal()
        );

        $this->assertNotNull($middleware);
    }

    public function testGetMiddlewareSuccedsIfNoDefaultFilesButIsOnGCE()
    {
        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            new Response(200, [], Utils::streamFor($jsonTokens)),
        ]);

        $this->assertNotNull(ApplicationDefaultCredentials::getMiddleware('a scope', $httpHandler));
    }

    public function testOnGceCacheWithHit()
    {
        $this->expectException(DomainException::class);

        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        $mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $mockCacheItem->isHit()
            ->willReturn(true);
        $mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(false);

        $mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $mockCache->getItem(GCECache::GCE_CACHE_KEY)
            ->shouldBeCalledTimes(1)
            ->willReturn($mockCacheItem->reveal());

        ApplicationDefaultCredentials::getMiddleware(
            'a scope',
            null,
            null,
            $mockCache->reveal()
        );
    }

    public function testOnGceCacheWithoutHit()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        $gceIsCalled = false;
        $dummyHandler = function ($request) use (&$gceIsCalled) {
            $gceIsCalled = true;
            return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
        };
        $mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $mockCacheItem->isHit()
            ->willReturn(false);
        $mockCacheItem->set(true)
            ->shouldBeCalledTimes(1)
            ->willReturn($mockCacheItem->reveal());
        $mockCacheItem->expiresAfter(1500)
            ->shouldBeCalledTimes(1)
            ->willReturn($mockCacheItem->reveal());

        $mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $mockCache->getItem(GCECache::GCE_CACHE_KEY)
            ->shouldBeCalledTimes(2)
            ->willReturn($mockCacheItem->reveal());
        $mockCache->save($mockCacheItem->reveal())
            ->shouldBeCalled();

        $creds = ApplicationDefaultCredentials::getMiddleware(
            'a scope',
            $dummyHandler,
            null,
            $mockCache->reveal()
        );

        $this->assertTrue($gceIsCalled);
    }

    public function testOnGceCacheWithOptions()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        $prefix = 'test_prefix_';
        $lifetime = '70707';

        $gceIsCalled = false;
        $dummyHandler = function ($request) use (&$gceIsCalled) {
            $gceIsCalled = true;
            return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
        };
        $mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $mockCacheItem->isHit()
            ->willReturn(false);
        $mockCacheItem->set(true)
            ->shouldBeCalledTimes(1)
            ->willReturn($mockCacheItem->reveal());
        $mockCacheItem->expiresAfter($lifetime)
            ->shouldBeCalledTimes(1)
            ->willReturn($mockCacheItem->reveal());

        $mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $mockCache->getItem($prefix . GCECache::GCE_CACHE_KEY)
            ->shouldBeCalledTimes(2)
            ->willReturn($mockCacheItem->reveal());
        $mockCache->save($mockCacheItem->reveal())
            ->shouldBeCalled();

        $creds = ApplicationDefaultCredentials::getMiddleware(
            'a scope',
            $dummyHandler,
            ['gce_prefix' => $prefix, 'gce_lifetime' => $lifetime],
            $mockCache->reveal()
        );

        $this->assertTrue($gceIsCalled);
    }

    public function testGetIdTokenCredentialsFailsIfEnvSpecifiesNonExistentFile()
    {
        $this->expectException(DomainException::class);

        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        ApplicationDefaultCredentials::getIdTokenCredentials($this->targetAudience);
    }

    public function testGetIdTokenCredentialsLoadsOKIfEnvSpecifiedIsValid()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $creds = ApplicationDefaultCredentials::getIdTokenCredentials($this->targetAudience);

        $this->assertNotNull($creds);
    }

    public function testGetIdTokenCredentialsLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        $creds = ApplicationDefaultCredentials::getIdTokenCredentials($this->targetAudience);
        $this->assertNotNull($creds);
    }

    public function testGetIdTokenCredentialsFailsIfNotOnGceAndNoDefaultFileFound()
    {
        $this->expectException(DomainException::class);

        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            new Response(500),
            new Response(500),
            new Response(500)
        ]);

        $creds = ApplicationDefaultCredentials::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler
        );

        $this->assertNotNull($creds);
    }

    public function testGetIdTokenCredentialsWithCacheOptions()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $httpHandler = getHandler([
            new Response(200),
        ]);

        $cacheOptions = [];
        $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

        $credentials = ApplicationDefaultCredentials::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler,
            $cacheOptions,
            $cachePool->reveal()
        );

        $this->assertInstanceOf('Google\Auth\FetchAuthTokenCache', $credentials);
    }

    public function testGetIdTokenCredentialsSuccedsIfNoDefaultFilesButIsOnGCE()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            new Response(200, [], Utils::streamFor($jsonTokens)),
        ]);

        $credentials = ApplicationDefaultCredentials::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\GCECredentials',
            $credentials
        );
    }

    public function testWithServiceAccountCredentialsAndExplicitQuotaProject()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $credentials = ApplicationDefaultCredentials::getCredentials(
            null,
            null,
            null,
            null,
            $this->quotaProject
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ServiceAccountCredentials',
            $credentials
        );

        $this->assertEquals(
            $this->quotaProject,
            $credentials->getQuotaProject()
        );
    }

    public function testGetCredentialsUtilizesQuotaProjectInKeyFile()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $credentials = ApplicationDefaultCredentials::getCredentials();

        $this->assertEquals(
            'test_quota_project',
            $credentials->getQuotaProject()
        );
    }

    /** @runInSeparateProcess */
    public function testGetCredentialsUtilizesQuotaProjectEnvVar()
    {
        $quotaProject = 'quota-project-from-env-var';
        putenv(CredentialsLoader::QUOTA_PROJECT_ENV_VAR . '=' . $quotaProject);
        putenv('HOME=' . __DIR__ . '/fixtures');

        $credentials = ApplicationDefaultCredentials::getCredentials();

        $this->assertEquals(
            $quotaProject,
            $credentials->getQuotaProject()
        );
    }

    /** @runInSeparateProcess */
    public function testGetCredentialsUtilizesQuotaProjectParameterOverEnvVar()
    {
        $quotaProject = 'quota-project-from-parameter';
        putenv(CredentialsLoader::QUOTA_PROJECT_ENV_VAR . '=quota-project-from-env-var');
        putenv('HOME=' . __DIR__ . '/fixtures');

        $credentials = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            $quotaProject, // $quotaProject
            null  // $defaultScope
        );

        $this->assertEquals(
            $quotaProject,
            $credentials->getQuotaProject()
        );
    }

    /** @runInSeparateProcess */
    public function testGetCredentialsUtilizesQuotaProjectEnvVarOverKeyFile()
    {
        $quotaProject = 'quota-project-from-env-var';
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(CredentialsLoader::QUOTA_PROJECT_ENV_VAR . '=' . $quotaProject);
        putenv(CredentialsLoader::ENV_VAR . '=' . $keyFile);

        $credentials = ApplicationDefaultCredentials::getCredentials();

        $this->assertEquals(
            $quotaProject,
            $credentials->getQuotaProject()
        );
    }

    public function testWithFetchAuthTokenCacheAndExplicitQuotaProject()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $httpHandler = getHandler([
            new Response(200),
        ]);

        $cacheOptions = [];
        $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

        $credentials = ApplicationDefaultCredentials::getCredentials(
            null,
            $httpHandler,
            $cacheOptions,
            $cachePool->reveal(),
            $this->quotaProject
        );

        $this->assertInstanceOf('Google\Auth\FetchAuthTokenCache', $credentials);

        $this->assertEquals(
            $this->quotaProject,
            $credentials->getQuotaProject()
        );
    }

    public function testWithGCECredentials()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            new Response(200, [], Utils::streamFor($jsonTokens)),
        ]);

        $credentials = ApplicationDefaultCredentials::getCredentials(
            null,
            $httpHandler,
            null,
            null,
            $this->quotaProject
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\GCECredentials',
            $credentials
        );

        $this->assertEquals(
            $this->quotaProject,
            $credentials->getQuotaProject()
        );
    }

    public function testAppEngineStandard()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        $this->assertInstanceOf(
            'Google\Auth\Credentials\AppIdentityCredentials',
            ApplicationDefaultCredentials::getCredentials()
        );
    }

    public function testAppEngineFlexible()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
        ]);
        $this->assertInstanceOf(
            'Google\Auth\Credentials\GCECredentials',
            ApplicationDefaultCredentials::getCredentials(null, $httpHandler)
        );
    }

    public function testAppEngineFlexibleIdToken()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
        ]);
        $creds = ApplicationDefaultCredentials::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler
        );
        $this->assertInstanceOf(
            'Google\Auth\Credentials\GCECredentials',
            $creds
        );
    }

    /**
     * @dataProvider provideExternalAccountCredentials
     */
    public function testExternalAccountCredentials(string $jsonFile, string $expectedCredSource)
    {
        putenv(sprintf('GOOGLE_APPLICATION_CREDENTIALS=%s/fixtures6/%s', __DIR__, $jsonFile));

        $creds = ApplicationDefaultCredentials::getCredentials('a_scope');

        $this->assertInstanceOf(ExternalAccountCredentials::class, $creds);

        $credsReflection = new \ReflectionClass($creds);
        $credsProp = $credsReflection->getProperty('auth');
        $credsProp->setAccessible(true);

        $oauth = $credsProp->getValue($creds);
        $oauthReflection = new \ReflectionClass($oauth);
        $oauthProp = $oauthReflection->getProperty('subjectTokenFetcher');
        $oauthProp->setAccessible(true);

        $subjectTokenFetcher = $oauthProp->getValue($oauth);
        $this->assertInstanceOf($expectedCredSource, $subjectTokenFetcher);
    }

    public function provideExternalAccountCredentials()
    {
        return [
            ['file_credentials.json', CredentialSource\FileSource::class],
            ['url_credentials.json', CredentialSource\UrlSource::class],
            ['aws_credentials.json', CredentialSource\AwsNativeSource::class],
            ['executable_credentials.json', CredentialSource\ExecutableSource::class],
        ];
    }

    /** @runInSeparateProcess */
    public function testUniverseDomainInKeyFile()
    {
        // Test no universe domain in keyfile defaults to "googleapis.com"
        $keyFile = __DIR__ . '/fixtures3/service_account_credentials.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $creds = ApplicationDefaultCredentials::getCredentials();
        $this->assertEquals(CredentialsLoader::DEFAULT_UNIVERSE_DOMAIN, $creds->getUniverseDomain());

        // Test universe domain in "service_account" keyfile
        $keyFile = __DIR__ . '/fixtures/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $creds = ApplicationDefaultCredentials::getCredentials();
        $this->assertEquals('example-universe.com', $creds->getUniverseDomain());

        // Test universe domain in "authenticated_user" keyfile is not read.
        $keyFile = __DIR__ . '/fixtures2/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $creds2 = ApplicationDefaultCredentials::getCredentials();
        $this->assertEquals(CredentialsLoader::DEFAULT_UNIVERSE_DOMAIN, $creds2->getUniverseDomain());

        // test passing in a different universe domain for "authenticated_user" has no effect.
        $creds3 = ApplicationDefaultCredentials::getCredentials(
            null,
            null,
            null,
            null,
            null,
            null,
            'example-universe2.com'
        );
        $this->assertEquals(CredentialsLoader::DEFAULT_UNIVERSE_DOMAIN, $creds3->getUniverseDomain());
    }

    /** @runInSeparateProcess */
    public function testUniverseDomainInGceCredentials()
    {
        putenv('HOME');

        $expectedUniverseDomain = 'example-universe.com';
        $creds = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            $httpHandler = getHandler([
                new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
                new Response(200, [], Utils::streamFor($expectedUniverseDomain)),
            ]) // $httpHandler
        );
        $this->assertEquals('example-universe.com', $creds->getUniverseDomain($httpHandler));

        // test passing in a different universe domain overrides metadata server
        $creds2 = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            $httpHandler = getHandler([
                new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            ]), // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            null, // $defaultScope
            'example-universe2.com' // $universeDomain
        );
        $this->assertEquals('example-universe2.com', $creds2->getUniverseDomain($httpHandler));

        // test error response returns default universe domain
        $creds2 = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            $httpHandler = getHandler([
                new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
                new Response(404),
            ]), // $httpHandler
        );
        $this->assertEquals(CredentialsLoader::DEFAULT_UNIVERSE_DOMAIN, $creds2->getUniverseDomain($httpHandler));
    }
}
