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

use Google\Auth\Credentials\ImpersonatedServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\UserRefreshCredentials;
use Google\Auth\Middleware\AuthTokenMiddleware;
use Google\Auth\OAuth2;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use LogicException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use ReflectionClass;

class ImpersonatedServiceAccountCredentialsTest extends TestCase
{
    private const SCOPE = ['scope/1', 'scope/2'];
    private const TARGET_AUDIENCE = 'test-target-audience';

    public function testGetServiceAccountNameEmail()
    {
        $json = $this->userToServiceAccountImpersonationJson;
        $creds = new ImpersonatedServiceAccountCredentials(self::SCOPE, $json);
        $this->assertEquals('test@test-project.iam.gserviceaccount.com', $creds->getClientName());
    }

    public function testGetServiceAccountNameID()
    {
        $json = $this->userToServiceAccountImpersonationJson;
        $json['service_account_impersonation_url'] = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/1234567890987654321:generateAccessToken';
        $creds = new ImpersonatedServiceAccountCredentials(self::SCOPE, $json);
        $this->assertEquals('1234567890987654321', $creds->getClientName());
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
     * @dataProvider provideServiceAccountImpersonationJson
     */
    public function testSourceCredentialsFromJsonFiles(array $json, string $credClass)
    {
        $creds = new ImpersonatedServiceAccountCredentials(['scope/1', 'scope/2'], $json);

        $sourceCredentialsProperty = (new ReflectionClass($creds))->getProperty('sourceCredentials');
        $sourceCredentialsProperty->setAccessible(true);
        $this->assertInstanceOf($credClass, $sourceCredentialsProperty->getValue($creds));
    }

    public function provideServiceAccountImpersonationJson()
    {
        return [
            [$this->userToServiceAccountImpersonationJson, UserRefreshCredentials::class],
            [$this->serviceAccountToServiceAccountImpersonationJson, ServiceAccountCredentials::class],
        ];
    }

    /**
     * @dataProvider provideServiceAccountImpersonationIdTokenJson
     */
    public function testGetIdTokenWithServiceAccountImpersonationCredentials($json, $grantType)
    {
        $creds = new ImpersonatedServiceAccountCredentials(null, $json, self::TARGET_AUDIENCE);

        $requestCount = 0;
        // getting an id token will take two requests
        $httpHandler = function (RequestInterface $request) use (&$requestCount, $json, $grantType) {
            if (++$requestCount == 1) {
                // the call to swap the refresh token for an access token
                $this->assertEquals(UserRefreshCredentials::TOKEN_CREDENTIAL_URI, (string) $request->getUri());
                $body = (string) $request->getBody();
                parse_str($body, $result);
                $this->assertEquals($grantType, $result['grant_type']);
            } elseif ($requestCount == 2) {
                // the call to swap the access token for an id token
                $this->assertEquals($json['service_account_impersonation_url'], (string) $request->getUri());
                $this->assertEquals(self::TARGET_AUDIENCE, json_decode($request->getBody(), true)['audience'] ?? '');
                $this->assertEquals('Bearer test-access-token', $request->getHeader('authorization')[0] ?? null);
            }

            return new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode(match ($requestCount) {
                    1 => ['access_token' => 'test-access-token'],
                    2 => ['token' => 'test-id-token']
                })
            );
        };

        $token = $creds->fetchAuthToken($httpHandler);
        $this->assertEquals(2, $requestCount);
        $this->assertEquals('test-id-token', $token['id_token']);
    }

    public function provideServiceAccountImpersonationIdTokenJson()
    {
        return [
            [$this->userToServiceAccountImpersonationIdTokenJson, 'refresh_token'],
            [$this->serviceAccountToServiceAccountImpersonationIdTokenJson, OAuth2::JWT_URN],
        ];
    }

    public function testIdTokenWithAuthTokenMiddleware()
    {
        $targetAudience = 'test-target-audience';
        $json = $this->userToServiceAccountImpersonationIdTokenJson;
        $credentials = new ImpersonatedServiceAccountCredentials(null, $json, $targetAudience);

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

    // User Refresh to Service Account Impersonation JSON Credentials
    private array $userToServiceAccountImpersonationJson = [
        'type' => 'impersonated_service_account',
        'service_account_impersonation_url' => 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@test-project.iam.gserviceaccount.com:generateAccessToken',
        'source_credentials' => [
            'client_id' => 'client123',
            'client_secret' => 'clientSecret123',
            'refresh_token' => 'refreshToken123',
            'type' => 'authorized_user',
        ]
    ];

    // Service Account to Service Account Impersonation JSON Credentials
    private array $serviceAccountToServiceAccountImpersonationJson = [
        'type' => 'impersonated_service_account',
        'service_account_impersonation_url' => 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@test-project.iam.gserviceaccount.com:generateAccessToken',
        'source_credentials' => [
            'client_email' => 'clientemail@clientemail.com',
            'private_key' => 'privatekey123',
            'type' => 'service_account',
        ]
    ];

    // User Refresh to Service Account Impersonation ID Token JSON Credentials
    // NOTE: The only difference is the use of "generateIdToken" instead of
    // "generateAccessToken" in the service_account_impersonation_url
    private array $userToServiceAccountImpersonationIdTokenJson = [
        'type' => 'impersonated_service_account',
        'service_account_impersonation_url' => 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@test-project.iam.gserviceaccount.com:generateIdToken',
        'source_credentials' => [
            'client_id' => 'client123',
            'client_secret' => 'clientSecret123',
            'refresh_token' => 'refreshToken123',
            'type' => 'authorized_user',
        ]
    ];

    // Service Account to Service Account Impersonation ID Token JSON Credentials
    // NOTE: The only difference is the use of "generateIdToken" instead of
    // "generateAccessToken" in the service_account_impersonation_url
    private array $serviceAccountToServiceAccountImpersonationIdTokenJson = [
        'type' => 'impersonated_service_account',
        'service_account_impersonation_url' => 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@test-project.iam.gserviceaccount.com:generateIdToken',
        'source_credentials' => [
            'client_email' => 'clientemail@clientemail.com',
            'private_key' => "-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgGhw1WMos5gp2YjV7+fNwXN1tI4/DFXKzwY6TDWsPxkbyfjHgunX\n/sijlnJt3Qs1gBxiwEEjzFFlp39O3/gEbIoYWHR/4sZdqNRFzbhJcTpnUvRlZDBL\nE5h8f5uu4aL4D32WyiELF/vpr533lZCBwWsnN3zIYJxThgRF9i/R7F8tAgMBAAEC\ngYAgUyv4cNSFOA64J18FY82IKtojXKg4tXi1+L01r4YoA03TzgxazBtzhg4+hHpx\nybFJF9dhUe8fElNxN7xiSxw8i5MnfPl+piwbfoENhgrzU0/N14AV/4Pq+WAJQe2M\nxPcI1DPYMEwGjX2PmxqnkC47MyR9agX21YZVc9rpRCgPgQJBALodH492I0ydvEUs\ngT+3DkNqoWx3O3vut7a0+6k+RkM1Yu+hGI8RQDCGwcGhQlOpqJkYGsVegZbxT+AF\nvvIFrIUCQQCPqJbRalHK/QnVj4uovj6JvjTkqFSugfztB4Zm/BPT2eEpjLt+851d\nIJ4brK/HVkQT2zk9eb0YzIBfeQi9WpyJAkB9+BRSf72or+KsV1EsFPScgOG9jn4+\nhfbmvVzQ0ouwFcRfOQRsYVq2/Z7LNiC0i9LHvF7yU+MWjUJo+LqjCWAZAkBHearo\nMIzXgQRGlC/5WgZFhDRO3A2d8aDE0eymCp9W1V24zYNwC4dtEVB5Fncyp5Ihiv40\nvwA9eWoZll+pzo55AkBMMdk95skWeaRv8T0G1duv5VQ7q4us2S2TKbEbC8j83BTP\nNefc3KEugylyAjx24ydxARZXznPi1SFeYVx1KCMZ\n-----END RSA PRIVATE KEY-----\n",
            'type' => 'service_account',
        ]
    ];
}
