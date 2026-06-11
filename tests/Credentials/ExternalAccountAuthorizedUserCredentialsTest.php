<?php


/*
 * Copyright 2026 Google Inc.
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

use Google\Auth\Credentials\ExternalAccountAuthorizedUserCredentials;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\RequestInterface;

/**
 * @group credentials
 * @group credentials-external-user
 */
class ExternalAccountAuthorizedUserCredentialsTest extends TestCase
{
    use ProphecyTrait;

    private $baseJsonKey = [
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'refresh_token' => 'refresh-token',
        'token_url' => 'http://token-url.com',
    ];

    public function testValidConstructor()
    {
        $creds = new ExternalAccountAuthorizedUserCredentials('scope', $this->baseJsonKey);
        $this->assertInstanceOf(ExternalAccountAuthorizedUserCredentials::class, $creds);
    }

    /**
     * @dataProvider provideInvalidJson
     */
    public function testInvalidConstructorThrowsException(array $jsonKey, string $expectedMessage)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedMessage);
        new ExternalAccountAuthorizedUserCredentials('scope', $jsonKey);
    }

    public function provideInvalidJson()
    {
        return [
            [
                [],
                'json key is missing the client_id field'
            ],
            [
                ['client_id' => 'id'],
                'json key is missing the client_secret field'
            ],
            [
                ['client_id' => 'id', 'client_secret' => 'secret'],
                'json key is missing the refresh_token field'
            ],
            [
                ['client_id' => 'id', 'client_secret' => 'secret', 'refresh_token' => 'token'],
                'json key is missing the token_url field'
            ],
        ];
    }

    public function testFetchAuthToken()
    {
        $scope = 'myscope';
        $creds = new ExternalAccountAuthorizedUserCredentials($scope, $this->baseJsonKey);
        $credsReflection = new \ReflectionClass(ExternalAccountAuthorizedUserCredentials::class);
        $authProp = $credsReflection->getProperty('auth');
        $authProp->setAccessible(true);
        $oauth2 = $authProp->getValue($creds);

        $expectedAuthToken = ['access_token' => 'new_access_token'];
        $mockHttpHandler = function (RequestInterface $request) use ($expectedAuthToken) {
            $this->assertEquals(
                'Basic ' . base64_encode('client-id:client-secret'),
                $request->getHeaderLine('Authorization')
            );
            $metricHeader = $request->getHeaderLine('x-goog-api-client');
            $this->assertStringContainsString('gl-php/', $metricHeader);
            $this->assertStringContainsString('auth/', $metricHeader);
            $this->assertStringContainsString('cred-type/eaau', $metricHeader);
            $this->assertStringContainsString('auth-request-type/at', $metricHeader);
            return new \GuzzleHttp\Psr7\Response(200, [], json_encode($expectedAuthToken));
        };

        $authToken = $creds->fetchAuthToken($mockHttpHandler);
        $this->assertEquals($expectedAuthToken, $authToken);
    }

    public function testGetCacheKey()
    {
        $scope = 'myscope';
        $creds = new ExternalAccountAuthorizedUserCredentials($scope, $this->baseJsonKey);
        $expectedKey = hash('sha256', implode('.', [
            $this->baseJsonKey['client_id'],
            $scope,
            $this->baseJsonKey['refresh_token']
        ]));
        $this->assertEquals($expectedKey, $creds->getCacheKey());
    }

    public function testGetCacheKeyWithDifferentRefreshTokensIsUnique()
    {
        $scope = 'myscope';
        $jsonKey1 = $this->baseJsonKey;
        $jsonKey2 = ['refresh_token' => 'different-refresh-token'] + $this->baseJsonKey;

        $creds1 = new ExternalAccountAuthorizedUserCredentials($scope, $jsonKey1);
        $creds2 = new ExternalAccountAuthorizedUserCredentials($scope, $jsonKey2);

        $this->assertNotEquals($creds1->getCacheKey(), $creds2->getCacheKey());
    }

    public function testGetUniverseDomain()
    {
        $jsonKey = ['universe_domain' => 'my-universe.com'] + $this->baseJsonKey;
        $creds = new ExternalAccountAuthorizedUserCredentials('scope', $jsonKey);
        $this->assertEquals('my-universe.com', $creds->getUniverseDomain());
    }

    public function testGetUniverseDomainDefault()
    {
        $creds = new ExternalAccountAuthorizedUserCredentials('scope', $this->baseJsonKey);
        $this->assertEquals('googleapis.com', $creds->getUniverseDomain());
    }

    public function testGetLastReceivedToken()
    {
        $creds = new ExternalAccountAuthorizedUserCredentials('scope', $this->baseJsonKey);
        $credsReflection = new \ReflectionClass(ExternalAccountAuthorizedUserCredentials::class);
        $authProp = $credsReflection->getProperty('auth');
        $authProp->setAccessible(true);
        $oauth2 = $authProp->getValue($creds);

        $token = [
            'access_token' => 'my_token',
            'expires_in' => 3600,
            'token_type' => 'Bearer',
        ];
        $oauth2->updateToken($token);

        $lastToken = $creds->getLastReceivedToken();
        $this->assertEquals($token['access_token'], $lastToken['access_token']);
        $this->assertEquals($token['expires_in'], $lastToken['expires_in']);
    }

    public function testGetQuotaProject()
    {
        $jsonKey = ['quota_project_id' => 'my-quota-project'] + $this->baseJsonKey;
        $creds = new ExternalAccountAuthorizedUserCredentials('scope', $jsonKey);
        $this->assertEquals('my-quota-project', $creds->getQuotaProject());
    }

    public function testGetQuotaProjectNotSet()
    {
        $creds = new ExternalAccountAuthorizedUserCredentials('scope', $this->baseJsonKey);
        $this->assertNull($creds->getQuotaProject());
    }

    public function testGetGrantedScope()
    {
        $creds = new ExternalAccountAuthorizedUserCredentials('scope', $this->baseJsonKey);
        $credsReflection = new \ReflectionClass(ExternalAccountAuthorizedUserCredentials::class);
        $authProp = $credsReflection->getProperty('auth');
        $authProp->setAccessible(true);
        $oauth2 = $authProp->getValue($creds);
        $oauth2->setGrantedScope('granted_scope');
        $this->assertEquals('granted_scope', $creds->getGrantedScope());
    }
}
