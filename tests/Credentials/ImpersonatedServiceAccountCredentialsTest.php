<?php

/*
 * Copyright 2022 Google Inc.
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

namespace Google\Auth\Tests\Credentials;

use Google\Auth\Credentials\ExternalAccountCredentials;
use Google\Auth\Credentials\ImpersonatedServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\UserRefreshCredentials;
use Google\Auth\FetchAuthTokenInterface;
use Google\Auth\GetUniverseDomainInterface;
use Google\Auth\Middleware\AuthTokenMiddleware;
use Google\Auth\OAuth2;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\RequestInterface;
use ReflectionClass;

class ImpersonatedServiceAccountCredentialsTest extends TestCase
{
    use ProphecyTrait;

    private const SCOPE = ['scope/1', 'scope/2'];
    private const TARGET_AUDIENCE = 'test-target-audience';
    private const IMPERSONATION_URL = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@test-project.iam.gserviceaccount.com:generateAccessToken';
    private const UNIVERSE_DOMAIN = 'example.com';

    // User Refresh to Service Account Impersonation JSON Credentials
    private const USER_TO_SERVICE_ACCOUNT_JSON = [
        'type' => 'impersonated_service_account',
        'service_account_impersonation_url' => self::IMPERSONATION_URL,
        'source_credentials' => [
            'client_id' => 'client123',
            'client_secret' => 'clientSecret123',
            'refresh_token' => 'refreshToken123',
            'type' => 'authorized_user',
        ]
    ];

    // Service Account to Service Account Impersonation JSON Credentials
    private const SERVICE_ACCOUNT_TO_SERVICE_ACCOUNT_JSON = [
        'type' => 'impersonated_service_account',
        'service_account_impersonation_url' => self::IMPERSONATION_URL,
        'source_credentials' => [
            'client_email' => 'clientemail@clientemail.com',
            'private_key' => "-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgGhw1WMos5gp2YjV7+fNwXN1tI4/DFXKzwY6TDWsPxkbyfjHgunX\n/sijlnJt3Qs1gBxiwEEjzFFlp39O3/gEbIoYWHR/4sZdqNRFzbhJcTpnUvRlZDBL\nE5h8f5uu4aL4D32WyiELF/vpr533lZCBwWsnN3zIYJxThgRF9i/R7F8tAgMBAAEC\ngYAgUyv4cNSFOA64J18FY82IKtojXKg4tXi1+L01r4YoA03TzgxazBtzhg4+hHpx\nybFJF9dhUe8fElNxN7xiSxw8i5MnfPl+piwbfoENhgrzU0/N14AV/4Pq+WAJQe2M\nxPcI1DPYMEwGjX2PmxqnkC47MyR9agX21YZVc9rpRCgPgQJBALodH492I0ydvEUs\ngT+3DkNqoWx3O3vut7a0+6k+RkM1Yu+hGI8RQDCGwcGhQlOpqJkYGsVegZbxT+AF\nvvIFrIUCQQCPqJbRalHK/QnVj4uovj6JvjTkqFSugfztB4Zm/BPT2eEpjLt+851d\nIJ4brK/HVkQT2zk9eb0YzIBfeQi9WpyJAkB9+BRSf72or+KsV1EsFPScgOG9jn4+\nhfbmvVzQ0ouwFcRfOQRsYVq2/Z7LNiC0i9LHvF7yU+MWjUJo+LqjCWAZAkBHearo\nMIzXgQRGlC/5WgZFhDRO3A2d8aDE0eymCp9W1V24zYNwC4dtEVB5Fncyp5Ihiv40\nvwA9eWoZll+pzo55AkBMMdk95skWeaRv8T0G1duv5VQ7q4us2S2TKbEbC8j83BTP\nNefc3KEugylyAjx24ydxARZXznPi1SFeYVx1KCMZ\n-----END RSA PRIVATE KEY-----\n",
            'type' => 'service_account',
        ]
    ];

    // Service Account to Service Account Impersonation JSON Credentials
    private const EXTERNAL_ACCOUNT_TO_SERVICE_ACCOUNT_JSON = [
        'type' => 'impersonated_service_account',
        'service_account_impersonation_url' => self::IMPERSONATION_URL,
        'source_credentials' => [
            'type' => 'external_account',
            'audience' => 'some_audience',
            'subject_token_type' => 'access_token',
            'token_url' => 'https://sts.googleapis.com/v1/token',
            'credential_source' => [
                'url' => 'https://some.url/token'
            ]
        ]
    ];

    public function testGetServiceAccountNameEmail()
    {
        $json = self::USER_TO_SERVICE_ACCOUNT_JSON;
        $creds = new ImpersonatedServiceAccountCredentials(self::SCOPE, $json);
        $this->assertEquals('test@test-project.iam.gserviceaccount.com', $creds->getClientName());
    }

    public function testGetServiceAccountNameID()
    {
        $json = self::USER_TO_SERVICE_ACCOUNT_JSON;
        $json['service_account_impersonation_url'] = 'https://some/arbitrary/url/serviceAccounts/1234567890987654321:generateAccessToken';
        $creds = new ImpersonatedServiceAccountCredentials(self::SCOPE, $json);
        $this->assertEquals('1234567890987654321', $creds->getClientName());
    }

    public function testGetCacheKey()
    {
        $creds = new ImpersonatedServiceAccountCredentials(self::SCOPE, [
            'service_account_impersonation_url' => 'foo',
            'source_credentials' => [
                'type' => 'service_account',
                'client_email' => '123',
                'private_key' => 'abc'
            ]
        ]);
        $this->assertEquals('foo123.scope1scope2', $creds->getCacheKey());
    }

    public function testMissingImpersonationUriThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('json key is missing the service_account_impersonation_url field');

        new ImpersonatedServiceAccountCredentials(self::SCOPE, []);
    }

    public function testMissingSourceCredentialTypeThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('json key source credentials are missing the type field');

        new ImpersonatedServiceAccountCredentials(self::SCOPE, [
            'service_account_impersonation_url' => 'https//google.com',
            'source_credentials' => []
        ]);
    }

    /**
     * @dataProvider provideSourceCredentialsClass
     */
    public function testSourceCredentialsClass(array $json, string $credClass)
    {
        $creds = new ImpersonatedServiceAccountCredentials(['scope/1', 'scope/2'], $json);

        $sourceCredentialsProperty = (new ReflectionClass($creds))->getProperty('sourceCredentials');
        $sourceCredentialsProperty->setAccessible(true);
        $this->assertInstanceOf($credClass, $sourceCredentialsProperty->getValue($creds));
    }

    public function provideSourceCredentialsClass()
    {
        return [
            [self::USER_TO_SERVICE_ACCOUNT_JSON, UserRefreshCredentials::class],
            [self::SERVICE_ACCOUNT_TO_SERVICE_ACCOUNT_JSON, ServiceAccountCredentials::class],
            [self::EXTERNAL_ACCOUNT_TO_SERVICE_ACCOUNT_JSON, ExternalAccountCredentials::class],
        ];
    }

    /**
     * Test access token impersonation for Service Account and User Refresh Credentials.
     *
     * @dataProvider provideAuthTokenJson
     */
    public function testGetAccessTokenWithServiceAccountAndUserRefreshCredentials(array $json, string $grantType)
    {
        $requestCount = 0;
        // getting an id token will take two requests
        $httpHandler = function (RequestInterface $request) use (&$requestCount, $json, $grantType) {
            if (++$requestCount == 1) {
                // the call to swap the refresh token for an access token
                $this->assertEquals(UserRefreshCredentials::TOKEN_CREDENTIAL_URI, (string) $request->getUri());
                parse_str((string) $request->getBody(), $result);
                $this->assertEquals($grantType, $result['grant_type']);
            } elseif ($requestCount == 2) {
                // the call to swap the access token for an id token
                $this->assertEquals($json['service_account_impersonation_url'], (string) $request->getUri());
                $this->assertEquals(self::SCOPE, json_decode($request->getBody(), true)['scope'] ?? '');
                $this->assertEquals('Bearer test-access-token', $request->getHeader('authorization')[0] ?? null);
            }

            return new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode(match ($requestCount) {
                    1 => ['access_token' => 'test-access-token'],
                    2 => ['accessToken' => 'test-impersonated-access-token', 'expireTime' => 123]
                })
            );
        };

        $creds = new ImpersonatedServiceAccountCredentials(self::SCOPE, $json);
        $token = $creds->fetchAuthToken($httpHandler);
        $this->assertEquals('test-impersonated-access-token', $token['access_token']);
        $this->assertEquals(2, $requestCount);
    }

    /**
     * Test access token impersonation for Exernal Account Credentials.
     */
    public function testGetAccessTokenWithExternalAccountCredentials()
    {
        $json = self::EXTERNAL_ACCOUNT_TO_SERVICE_ACCOUNT_JSON;
        $httpHandler = function (RequestInterface $request) use (&$requestCount, $json) {
            if (++$requestCount == 1) {
                // the call to swap the refresh token for an access token
                $this->assertEquals(
                    $json['source_credentials']['credential_source']['url'],
                    (string) $request->getUri()
                );
            } elseif ($requestCount == 2) {
                $this->assertEquals($json['source_credentials']['token_url'], (string) $request->getUri());
            } elseif ($requestCount == 3) {
                // the call to swap the access token for an id token
                $this->assertEquals($json['service_account_impersonation_url'], (string) $request->getUri());
                $this->assertEquals(self::SCOPE, json_decode($request->getBody(), true)['scope'] ?? '');
                $this->assertEquals('Bearer test-access-token', $request->getHeader('authorization')[0] ?? null);
            }

            return new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode(match ($requestCount) {
                    1 => ['access_token' => 'test-access-token'],
                    2 => ['access_token' => 'test-access-token'],
                    3 => ['accessToken' => 'test-impersonated-access-token', 'expireTime' => 123]
                })
            );
        };

        $creds = new ImpersonatedServiceAccountCredentials(self::SCOPE, $json);
        $token = $creds->fetchAuthToken($httpHandler);
        $this->assertEquals('test-impersonated-access-token', $token['access_token']);
        $this->assertEquals(3, $requestCount);
    }

    /**
     * Test ID token impersonation for Service Account and User Refresh Credentials.
     *
     * @dataProvider provideAuthTokenJson
     */
    public function testGetIdTokenWithServiceAccountAndUserRefreshCredentials(array $json, string $grantType)
    {
        $requestCount = 0;
        // getting an id token will take two requests
        $httpHandler = function (RequestInterface $request) use (&$requestCount, $json, $grantType) {
            if (++$requestCount == 1) {
                // the call to swap the refresh token for an access token
                $this->assertEquals(UserRefreshCredentials::TOKEN_CREDENTIAL_URI, (string) $request->getUri());
                parse_str((string) $request->getBody(), $result);
                $this->assertEquals($grantType, $result['grant_type']);
            } elseif ($requestCount == 2) {
                // the call to swap the access token for an id token
                $this->assertEquals(
                    str_replace(':generateAccessToken', ':generateIdToken', $json['service_account_impersonation_url']),
                    (string) $request->getUri()
                );
                $this->assertEquals(self::TARGET_AUDIENCE, json_decode($request->getBody(), true)['audience'] ?? '');
                $this->assertEquals('Bearer test-access-token', $request->getHeader('authorization')[0] ?? null);
            }

            return new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode(match ($requestCount) {
                    1 => ['access_token' => 'test-access-token'],
                    2 => ['token' => 'test-impersonated-id-token']
                })
            );
        };

        $creds = new ImpersonatedServiceAccountCredentials(null, $json, self::TARGET_AUDIENCE);
        $token = $creds->fetchAuthToken($httpHandler);
        $this->assertEquals('test-impersonated-id-token', $token['id_token']);
        $this->assertEquals(2, $requestCount);
    }

    public function provideAuthTokenJson()
    {
        return [
            [self::USER_TO_SERVICE_ACCOUNT_JSON, 'refresh_token'],
            [self::SERVICE_ACCOUNT_TO_SERVICE_ACCOUNT_JSON, OAuth2::JWT_URN],
        ];
    }

    /**
     * Test ID token impersonation for Service Account Credentials with a universe domain.
     */
    public function testGetIdTokenWithServiceAccountCredentialsAndUniverseDomain()
    {
        $json = self::SERVICE_ACCOUNT_TO_SERVICE_ACCOUNT_JSON;
        $json['source_credentials']['universe_domain'] = self::UNIVERSE_DOMAIN;

        // the expected URL should have the universe domain
        $expectedUrl = str_replace(
            ['googleapis.com', ':generateAccessToken'],
            [self::UNIVERSE_DOMAIN, ':generateIdToken'],
            $json['service_account_impersonation_url'],
        );

        // getting an id token will take two requests
        $httpHandler = function (RequestInterface $request) use ($expectedUrl) {
            $this->assertEquals($expectedUrl, (string) $request->getUri());
            $this->assertEquals(self::TARGET_AUDIENCE, json_decode($request->getBody(), true)['audience'] ?? '');
            $this->assertStringStartsWith('Bearer ', $request->getHeader('authorization')[0] ?? null);

            return new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode(['token' => 'test-impersonated-id-token'])
            );
        };

        $creds = new ImpersonatedServiceAccountCredentials(null, $json, self::TARGET_AUDIENCE);
        $token = $creds->fetchAuthToken($httpHandler);
        $this->assertEquals('test-impersonated-id-token', $token['id_token']);
    }

    /**
     * Test invalid email throws exception
     */
    public function testInvalidServiceAccountImpersonationUrlThrowsException()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid service account impersonation URL - unable to parse service account email'
        );

        $json = self::SERVICE_ACCOUNT_TO_SERVICE_ACCOUNT_JSON;
        $json['service_account_impersonation_url'] = 'https://invalid/url';

        // mock access token call for source credentials
        $httpHandler = fn () => new Response(
            200,
            ['Content-Type' => 'application/json'],
            json_encode(['access_token' => 'test-access-token'])
        );

        $creds = new ImpersonatedServiceAccountCredentials(null, $json, self::TARGET_AUDIENCE);
        $creds->fetchAuthToken($httpHandler);
    }

    /**
     * Test ID token impersonation for Exernal Account Credentials.
     * @dataProvider provideUniverseDomain
     */
    public function testGetIdTokenWithExternalAccountCredentials(?string $universeDomain = null)
    {
        $json = self::EXTERNAL_ACCOUNT_TO_SERVICE_ACCOUNT_JSON;
        if ($universeDomain) {
            $json['source_credentials']['universe_domain'] = $universeDomain;
        }
        $httpHandler = function (RequestInterface $request) use (&$requestCount, $json, $universeDomain) {
            if (++$requestCount == 1) {
                // the call to swap the refresh token for an access token
                $this->assertEquals(
                    $json['source_credentials']['credential_source']['url'],
                    (string) $request->getUri()
                );
            } elseif ($requestCount == 2) {
                $this->assertEquals($json['source_credentials']['token_url'], (string) $request->getUri());
            } elseif ($requestCount == 3) {
                // the call to swap the access token for an id token
                $url = str_replace(':generateAccessToken', ':generateIdToken', $json['service_account_impersonation_url']);
                if ($universeDomain) {
                    $url = str_replace('googleapis.com', $universeDomain, $url);
                }
                $this->assertEquals($url, (string) $request->getUri());
                $this->assertEquals(self::TARGET_AUDIENCE, json_decode($request->getBody(), true)['audience'] ?? '');
                $this->assertEquals('Bearer test-access-token', $request->getHeader('authorization')[0] ?? null);
            }

            return new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode(match ($requestCount) {
                    1 => ['access_token' => 'test-access-token'],
                    2 => ['access_token' => 'test-access-token'],
                    3 => ['token' => 'test-impersonated-id-token']
                })
            );
        };

        $creds = new ImpersonatedServiceAccountCredentials(null, $json, self::TARGET_AUDIENCE);
        $token = $creds->fetchAuthToken($httpHandler);
        $this->assertEquals('test-impersonated-id-token', $token['id_token']);
        $this->assertEquals(3, $requestCount);
    }

    /**
     * Test ID token impersonation for an arbitrary credential fetcher.
     * @dataProvider provideUniverseDomain
     */
    public function testGetIdTokenWithArbitraryCredentials(?string $universeDomain = null)
    {
        $url = $universeDomain
            ? 'https://iamcredentials.' . self::UNIVERSE_DOMAIN . '/v1/projects/-/serviceAccounts/123:generateIdToken'
            : 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/123:generateIdToken';

        $httpHandler = function (RequestInterface $request) use ($url) {
            // The URL is coerced to match the googleapis URL pattern
            $this->assertEquals($url, (string) $request->getUri());
            $this->assertEquals('Bearer test-access-token', $request->getHeader('authorization')[0] ?? null);
            return new Response(200, [], json_encode(['token' => 'test-impersonated-id-token']));
        };

        $credentials = $this->prophesize(FetchAuthTokenInterface::class)
            ->willImplement(GetUniverseDomainInterface::class);
        $credentials->fetchAuthToken($httpHandler, Argument::type('array'))
            ->shouldBeCalledOnce()
            ->willReturn(['access_token' => 'test-access-token']);
        $credentials->getUniverseDomain()
            ->shouldBeCalledOnce()
            ->willReturn($universeDomain ?: GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN);

        $json = [
            'type' => 'impersonated_service_account',
            'service_account_impersonation_url' => 'https://some/url/serviceAccounts/123:generateAccessToken',
            'source_credentials' => $credentials->reveal(),
        ];

        $creds = new ImpersonatedServiceAccountCredentials(null, $json, self::TARGET_AUDIENCE);

        $token = $creds->fetchAuthToken($httpHandler);
        $this->assertEquals('test-impersonated-id-token', $token['id_token']);
    }

    public function provideUniverseDomain()
    {
        return [
            [null],
            [self::UNIVERSE_DOMAIN],
        ];
    }

    /**
     * Test access token impersonation for an arbitrary credential fetcher.
     */
    public function testGetAccessTokenWithArbitraryCredentials()
    {
        $httpHandler = function (RequestInterface $request) {
            $this->assertEquals('https://some/url', (string) $request->getUri());
            $this->assertEquals('Bearer test-access-token', $request->getHeader('authorization')[0] ?? null);
            return new Response(
                200,
                [],
                json_encode(['accessToken' => 'test-impersonated-access-token', 'expireTime' => 123])
            );
        };

        $credentials = $this->prophesize(FetchAuthTokenInterface::class);
        $credentials->fetchAuthToken($httpHandler, Argument::type('array'))
            ->shouldBeCalledOnce()
            ->willReturn(['access_token' => 'test-access-token']);

        $json = [
            'type' => 'impersonated_service_account',
            'service_account_impersonation_url' => 'https://some/url',
            'source_credentials' => $credentials->reveal(),
        ];
        $creds = new ImpersonatedServiceAccountCredentials(self::SCOPE, $json);

        $token = $creds->fetchAuthToken($httpHandler);
        $this->assertEquals('test-impersonated-access-token', $token['access_token']);
    }

    public function testIdTokenWithAuthTokenMiddleware()
    {
        $targetAudience = 'test-target-audience';
        $credentials = new ImpersonatedServiceAccountCredentials(null, self::USER_TO_SERVICE_ACCOUNT_JSON, $targetAudience);

        // this handler is for the middleware constructor, which will pass it to the ISAC to fetch tokens
        $httpHandler = getHandler([
            new Response(200, ['Content-Type' => 'application/json'], '{"access_token":"this.is.an.access.token"}'),
            new Response(200, ['Content-Type' => 'application/json'], '{"token":"this.is.an.id.token"}'),
        ]);
        $middleware = new AuthTokenMiddleware($credentials, $httpHandler);

        // this handler is the actual handler that makes the authenticated request
        $requestCount = 0;
        $httpHandler = function (RequestInterface $request) use (&$requestCount) {
            $requestCount++;
            $this->assertTrue($request->hasHeader('authorization'));
            $this->assertEquals('Bearer this.is.an.id.token', $request->getHeader('authorization')[0] ?? null);
        };

        $middleware($httpHandler)(
            new Request('GET', 'https://www.google.com'),
            ['auth' => 'google_auth']
        );

        $this->assertEquals(1, $requestCount);
    }
}
