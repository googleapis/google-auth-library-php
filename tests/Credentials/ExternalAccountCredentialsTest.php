<?php
/*
 * Copyright 2023 Google Inc.
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
use Google\Auth\CredentialSource\AwsNativeSource;
use Google\Auth\CredentialSource\FileSource;
use Google\Auth\CredentialSource\UrlSource;
use Google\Auth\OAuth2;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * @group credentials
 * @group credentials-external
 */
class ExternalAccountCredentialsTest extends TestCase
{
    use ProphecyTrait;

    /**
     * @dataProvider provideCredentialSourceFromCredentials
     */
    public function testCredentialSourceFromCredentials(
        array $credentialSource,
        string $expectedSourceClass,
        array $expectedProperties = []
    ) {
        $jsonCreds = [
            'type' => 'external_account',
            'token_url' => '',
            'audience' => '',
            'subject_token_type' => '',
            'credential_source' => $credentialSource,
        ];

        $credsReflection = new \ReflectionClass(ExternalAccountCredentials::class);
        $credsProp = $credsReflection->getProperty('auth');
        $credsProp->setAccessible(true);

        $creds = new ExternalAccountCredentials('a-scope', $jsonCreds);
        $oauth = $credsProp->getValue($creds);

        $oauthReflection = new \ReflectionClass(OAuth2::class);
        $oauthProp = $oauthReflection->getProperty('subjectTokenFetcher');
        $oauthProp->setAccessible(true);
        $subjectTokenFetcher = $oauthProp->getValue($oauth);

        $this->assertInstanceOf($expectedSourceClass, $subjectTokenFetcher);

        $sourceReflection = new \ReflectionClass($subjectTokenFetcher);
        foreach ($expectedProperties as $propName => $expectedPropValue) {
            $sourceProp = $sourceReflection->getProperty($propName);
            $sourceProp->setAccessible(true);
            $this->assertEquals($expectedPropValue, $sourceProp->getValue($subjectTokenFetcher));
        }
    }

    public function provideCredentialSourceFromCredentials()
    {
        return [
            [
                [
                    'environment_id' => 'aws1',
                    'regional_cred_verification_url' => 'abc',
                    'region_url' => 'def',
                    'url' => 'ghi',
                    'imdsv2_session_token_url' => 'jkl'
                ],
                AwsNativeSource::class,
                [
                    'regionalCredVerificationUrl' => 'abc',
                    'regionUrl' => 'def',
                    'securityCredentialsUrl' => 'ghi',
                    'imdsv2SessionTokenUrl' => 'jkl',
                ],
            ],
            [
                ['file' => 'path/to/credsfile.json', 'format' => ['type' => 'json', 'subject_token_field_name' => 'token']],
                FileSource::class,
                [
                    'format' => 'json',
                    'subjectTokenFieldName' => 'token',
                ]
            ],
            [
                ['url' => 'https://test.com'],
                UrlSource::class
            ],
            [
                ['url' => 'https://test.com', 'format' => ['type' => 'json', 'subject_token_field_name' => 'token']],
                UrlSource::class
            ],
            [
                [
                    'url' => 'https://test.com',
                    'format' => [
                        'type' => 'json',
                        'subject_token_field_name' => 'token',
                    ],
                    'headers' => ['foo' => 'bar'],
                ],
                UrlSource::class,
                [
                    'format' => 'json',
                    'subjectTokenFieldName' => 'token',
                    'headers' => ['foo' => 'bar'],
                ]
            ],
        ];
    }

    /**
     * @dataProvider provideInvalidCredentialsJson
     */
    public function testInvalidCredentialsJsonThrowsException(array $json, string $exceptionMessage)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($exceptionMessage);

        new ExternalAccountCredentials('a-scope', $json);
    }

    public function provideInvalidCredentialsJson()
    {
        return [
            [
                [],
                'json key is missing the type field'
            ],
            [
                ['type' => 'foo'],
                'expected "external_account" type but received "foo"'
            ],
            [
                ['type' => 'external_account'],
                'json key is missing the token_url field'
            ],
            [
                ['type' => 'external_account', 'token_url' => ''],
                'json key is missing the audience field'
            ],
            [
                ['type' => 'external_account', 'token_url' => '', 'audience' => ''],
                'json key is missing the subject_token_type field'
            ],
            [
                ['type' => 'external_account', 'token_url' => '', 'audience' => '', 'subject_token_type' => ''],
                'json key is missing the credential_source field'
            ],
            [
                ['type' => 'external_account', 'token_url' => '', 'audience' => '', 'subject_token_type' => '', 'credential_source' => []],
                'Unable to determine credential source from json key'
            ],
            [
                ['type' => 'external_account', 'token_url' => '', 'audience' => '', 'subject_token_type' => '', 'credential_source' => [
                    'environment_id' => 'aws2',
                ]],
                'aws version "2" is not supported in the current build.'
            ],
            [
                ['type' => 'external_account', 'token_url' => '', 'audience' => '', 'subject_token_type' => '', 'credential_source' => [
                    'environment_id' => 'aws1',
                ]],
                'The regional_cred_verification_url field is required for aws1 credential source.'
            ],
            [
                ['type' => 'external_account', 'token_url' => '', 'audience' => '', 'subject_token_type' => '', 'credential_source' => [
                    'environment_id' => 'aws1',
                    'region_url' => '',
                ]],
                'The regional_cred_verification_url field is required for aws1 credential source.'
            ],
        ];
    }

    public function testFetchAuthTokenFileCredentials()
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmpFile, 'abc');

        $jsonCreds = [
            'type' => 'external_account',
            'token_url' => 'token-url.com',
            'audience' => '',
            'subject_token_type' => '',
            'credential_source' => ['file' => $tmpFile],
        ];

        $creds = new ExternalAccountCredentials('a-scope', $jsonCreds);

        $httpHandler = function (RequestInterface $request) {
            $this->assertEquals('token-url.com', (string) $request->getUri());
            parse_str((string) $request->getBody(), $requestBody);
            $this->assertEquals('abc', $requestBody['subject_token']);

            $responseBody = $this->prophesize(StreamInterface::class);
            $responseBody->__toString()->willReturn(json_encode(['access_token' => 'def', 'expires_in' => 1000]));

            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($responseBody->reveal());
            $response->hasHeader('Content-Type')->willReturn(false);

            return $response->reveal();
        };

        $authToken = $creds->fetchAuthToken($httpHandler);
        $this->assertArrayHasKey('access_token', $authToken);
        $this->assertEquals('def', $authToken['access_token']);
    }

    public function testFetchAuthTokenUrlCredentials()
    {
        $jsonCreds = [
            'type' => 'external_account',
            'token_url' => 'token-url.com',
            'audience' => '',
            'subject_token_type' => '',
            'credential_source' => ['url' => 'sts-url.com'],
        ];

        $creds = new ExternalAccountCredentials('a-scope', $jsonCreds);

        $requestCount = 0;
        $httpHandler = function (RequestInterface $request) use (&$requestCount) {
            switch (++$requestCount) {
                case 1:
                    $this->assertEquals('sts-url.com', (string) $request->getUri());
                    $responseBody = 'abc';
                    break;

                case 2:
                    $this->assertEquals('token-url.com', (string) $request->getUri());
                    parse_str((string) $request->getBody(), $requestBody);
                    $this->assertEquals('abc', $requestBody['subject_token']);
                    $responseBody = '{"access_token": "def"}';
                    break;
            }

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn($responseBody);

            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());
            if ($requestCount === 2) {
                $response->hasHeader('Content-Type')->willReturn(false);
            }

            return $response->reveal();
        };

        $authToken = $creds->fetchAuthToken($httpHandler);
        $this->assertArrayHasKey('access_token', $authToken);
        $this->assertEquals('def', $authToken['access_token']);
    }

    public function testFetchAuthTokenWithImpersonation()
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmpFile, 'abc');

        $jsonCreds = [
            'type' => 'external_account',
            'token_url' => 'token-url.com',
            'audience' => '',
            'subject_token_type' => '',
            'credential_source' => ['file' => $tmpFile],
            'service_account_impersonation_url' => 'service-account-impersonation-url.com',
        ];

        $creds = new ExternalAccountCredentials('a-scope', $jsonCreds);

        $requestCount = 0;
        $expiry = '2023-10-05T18:00:01Z';
        $httpHandler = function (RequestInterface $request) use (&$requestCount, $expiry) {
            switch (++$requestCount) {
                case 1:
                    $this->assertEquals('token-url.com', (string) $request->getUri());
                    parse_str((string) $request->getBody(), $requestBody);
                    $this->assertEquals('abc', $requestBody['subject_token']);
                    $responseBody = '{"access_token": "def"}';
                    break;
                case 2:
                    $this->assertEquals('service-account-impersonation-url.com', (string) $request->getUri());
                    $responseBody = json_encode(['accessToken' => 'def', 'expireTime' => $expiry]);
                    break;
            }

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn($responseBody);

            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());
            if ($requestCount === 1) {
                $response->hasHeader('Content-Type')->willReturn(false);
            }

            return $response->reveal();
        };

        $authToken = $creds->fetchAuthToken($httpHandler);
        $this->assertArrayHasKey('access_token', $authToken);
        $this->assertEquals('def', $authToken['access_token']);
        $this->assertEquals(strtotime($expiry), $authToken['expires_at']);
    }

    public function testGetQuotaProject()
    {
        $jsonCreds = [
            'type' => 'external_account',
            'token_url' => 'token-url.com',
            'audience' => '',
            'subject_token_type' => '',
            'credential_source' => ['url' => 'sts-url.com'],
            'quota_project_id' => 'test_quota_project',
        ];

        $creds = new ExternalAccountCredentials('a-scope', $jsonCreds);
        $this->assertEquals('test_quota_project', $creds->getQuotaProject());
    }
}
