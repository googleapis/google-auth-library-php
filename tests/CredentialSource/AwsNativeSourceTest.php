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

use Google\Auth\CredentialSource\AwsNativeSource;
use LogicException;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * @group credentials
 * @group credentials-iam
 */
class AwsNativeSourceTest extends TestCase
{
    use ProphecyTrait;

    private string $regionUrl = 'https://test.regional.url';
    private string $regionalCredVerificationUrl = 'https://test.regional.cred.verification.url';
    private string $securityCredentialsUrl = 'https://test.security.credentials.url';

    public function testGetRegion()
    {
        $handler = function (RequestInterface $request): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals($this->regionUrl, (string) $request->getUri());

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn('us-east-2b');
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        $region = AwsNativeSource::getRegion($handler, $this->regionUrl);
        $this->assertEquals('us-east-2', $region);
    }

    public function testGetRoleName()
    {
        $handler = function (RequestInterface $request): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals($this->securityCredentialsUrl, (string) $request->getUri());

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn('expected-role-name');
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        $roleName = AwsNativeSource::getRoleName($handler, $this->securityCredentialsUrl);

        $this->assertEquals('expected-role-name', $roleName);
    }

    public function testGetSigningVarsFromUrl()
    {
        $handler = function (RequestInterface $request): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals(
                $this->securityCredentialsUrl . '/test-role-name',
                (string) $request->getUri()
            );

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn(json_encode([
                'AccessKeyId' => 'expected-access-key-id',
                'SecretAccessKey' => 'expected-secret-access-key',
                'Token' => 'expected-token',
            ]));
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        $signingVars = AwsNativeSource::getSigningVarsFromUrl(
            $handler,
            $this->securityCredentialsUrl,
            'test-role-name'
        );

        $this->assertEquals('expected-access-key-id', $signingVars[0]);
        $this->assertEquals('expected-secret-access-key', $signingVars[1]);
        $this->assertEquals('expected-token', $signingVars[2]);
    }

    /** @runInSeparateProcess */
    public function testGetSigningVarsFromEnv()
    {
        // Without any environment variables set, getSigningVarsFromEnv should return null
        $signingVars = AwsNativeSource::getSigningVarsFromEnv();

        $this->assertNull($signingVars);

        // Requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to be set
        $_ENV['AWS_ACCESS_KEY_ID'] = 'expected-access-key-id';
        $_ENV['AWS_SECRET_ACCESS_KEY'] = 'expected-secret-access-key';

        $signingVars = AwsNativeSource::getSigningVarsFromEnv();
        $this->assertEquals('expected-access-key-id', $signingVars[0]);
        $this->assertEquals('expected-secret-access-key', $signingVars[1]);
        $this->assertNull($signingVars[2]);

        // AWS_SESSION_TOKEN is optional
        $_ENV['AWS_SESSION_TOKEN'] = 'expected-session-token';

        $signingVars = AwsNativeSource::getSigningVarsFromEnv();
        $this->assertEquals('expected-access-key-id', $signingVars[0]);
        $this->assertEquals('expected-secret-access-key', $signingVars[1]);
        $this->assertEquals('expected-session-token', $signingVars[2]);
    }

    public function testGetSignedRequestHeaders()
    {
        $region = 'us-east-2';
        $accessKeyId = 'expected-access-key-id';
        $secretAccessKey = 'expected-secret-access-key';
        $securityToken = null;
        $headers = AwsNativeSource::getSignedRequestHeaders(
            $region,
            $accessKeyId,
            $secretAccessKey,
            $securityToken
        );

        $this->assertArrayHasKey('x-amz-date', $headers);
        $this->assertArrayHasKey('Authorization', $headers);
        $this->assertArrayNotHasKey('x-amz-security-token', $headers);
        $this->assertStringStartsWith('AWS4-HMAC-SHA256 ', $headers['Authorization']);
        $this->assertStringContainsString(
            ' Credential=expected-access-key-id/',
            $headers['Authorization']
        );
        $this->assertStringContainsString(
            '/us-east-2/sts/aws4_request, SignedHeaders=host;x-amz-date, ',
            $headers['Authorization']
        );
        $this->assertStringContainsString(
            ', Signature=',
            $headers['Authorization']
        );

        $securityToken = 'extected-security-token';
        $headers = AwsNativeSource::getSignedRequestHeaders(
            $region,
            $accessKeyId,
            $secretAccessKey,
            $securityToken
        );

        $this->assertArrayHasKey('x-amz-date', $headers);
        $this->assertArrayHasKey('Authorization', $headers);
        $this->assertArrayHasKey('x-amz-security-token', $headers);
        $this->assertStringStartsWith('AWS4-HMAC-SHA256 ', $headers['Authorization']);
        $this->assertStringContainsString(
            ' Credential=expected-access-key-id/',
            $headers['Authorization']
        );
        $this->assertStringContainsString(
            '/us-east-2/sts/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, ',
            $headers['Authorization']
        );
        $this->assertStringContainsString(
            ', Signature=',
            $headers['Authorization']
        );
    }

    public function testFetchAccessTokenFromCredVerificationUrl()
    {
        $handler = function (RequestInterface $request): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals(
                'Action=GetCallerIdentity&Version=2011-06-15',
                (string) $request->getUri()->getQuery()
            );
            $this->assertEquals(
                $this->regionalCredVerificationUrl,
                'https://' . $request->getUri()->getHost()
            );

            $this->assertEquals(
                'test-value',
                $request->getHeaderLine('test-header')
            );

            // Mock response from Regional Credential Verification URL
            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn(json_encode(['access_token' => 'abc']));
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        $headers = ['test-header' => 'test-value'];

        $accessToken = AwsNativeSource::fetchAccessTokenFromCredVerificationUrl(
            $handler,
            $this->regionalCredVerificationUrl,
            $headers
        );

        $this->assertEquals('abc', $accessToken);
    }

    public function testFetchAccessTokenWithoutSecurityCredentialsUrlOrEnvThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'Unable to get credentials from ENV, and no security credentials URL provided'
        );

        $aws = new AwsNativeSource(
            $this->regionUrl,
            $this->regionalCredVerificationUrl,
        );
        $aws->fetchAuthToken();
    }

    /**
     * @runInSeparateProcess
     */
    public function testFetchAccessTokenFromEnv()
    {
        $aws = new AwsNativeSource(
            $this->regionUrl,
            $this->regionalCredVerificationUrl,
        );

        // Set minimum number of environment variables required
        $_ENV['AWS_ACCESS_KEY_ID'] = 'expected-access-key-id';
        $_ENV['AWS_SECRET_ACCESS_KEY'] = 'expected-secret-access-key';

        // Mock response from Region URL
        $regionBody = $this->prophesize(StreamInterface::class);
        $regionBody->__toString()->willReturn('us-east-2b');
        $regionResponse = $this->prophesize(ResponseInterface::class);
        $regionResponse->getBody()->willReturn($regionBody->reveal());

        // Mock response from Regional Credential Verification URL
        $credVerificationBody = $this->prophesize(StreamInterface::class);
        $credVerificationBody->__toString()->willReturn(json_encode(['access_token' => 'abc']));
        $credVerificationResponse = $this->prophesize(ResponseInterface::class);
        $credVerificationResponse->getBody()->willReturn($credVerificationBody->reveal());

        $requestCount = 0;
        $handler = function (RequestInterface $request) use (
            $regionResponse,
            $credVerificationResponse,
            &$requestCount
        ): ResponseInterface {
            $requestCount++;
            switch ($requestCount) {
                case 1: return $regionResponse->reveal();
                case 2: return $credVerificationResponse->reveal();
            }
        };

        $accessToken = $aws->fetchAuthToken($handler);
        $this->assertArrayHasKey('access_token', $accessToken);
        $this->assertEquals('abc', $accessToken['access_token']);
    }

    public function testFetchAccessTokenFromUrl()
    {
        $aws = new AwsNativeSource(
            $this->regionUrl,
            $this->regionalCredVerificationUrl,
            $this->securityCredentialsUrl
        );

        // Mock response from Role Name request
        $roleBody = $this->prophesize(StreamInterface::class);
        $roleBody->__toString()->willReturn('test-role-name');
        $roleResponse = $this->prophesize(ResponseInterface::class);
        $roleResponse->getBody()->willReturn($roleBody->reveal());

        // Mock response from Security Credentials URL
        $securityCredentialsBody = $this->prophesize(StreamInterface::class);
        $securityCredentialsBody->__toString()->willReturn(json_encode([
            'AccessKeyId' => 'test-access-key-id',
            'SecretAccessKey' => 'test-secret-access-key',
            'Token' => 'test-token',
        ]));
        $securityCredentialsResponse = $this->prophesize(ResponseInterface::class);
        $securityCredentialsResponse->getBody()->willReturn($securityCredentialsBody->reveal());

        // Mock response from Region URL
        $regionBody = $this->prophesize(StreamInterface::class);
        $regionBody->__toString()->willReturn('us-east-2b');
        $regionResponse = $this->prophesize(ResponseInterface::class);
        $regionResponse->getBody()->willReturn($regionBody->reveal());

        // Mock response from Regional Credential Verification URL
        $credVerificationBody = $this->prophesize(StreamInterface::class);
        $credVerificationBody->__toString()->willReturn(json_encode(['access_token' => 'abc']));
        $credVerificationResponse = $this->prophesize(ResponseInterface::class);
        $credVerificationResponse->getBody()->willReturn($credVerificationBody->reveal());

        $requestCount = 0;
        $handler = function (RequestInterface $request) use (
            $roleResponse,
            $securityCredentialsResponse,
            $regionResponse,
            $credVerificationResponse,
            &$requestCount
        ): ResponseInterface {
            $requestCount++;
            switch ($requestCount) {
                case 1: return $roleResponse->reveal();
                case 2: return $securityCredentialsResponse->reveal();
                case 3: return $regionResponse->reveal();
                case 4: return $credVerificationResponse->reveal();
            }
        };

        $accessToken = $aws->fetchAuthToken($handler);
        $this->assertArrayHasKey('access_token', $accessToken);
        $this->assertEquals('abc', $accessToken['access_token']);
    }
}
