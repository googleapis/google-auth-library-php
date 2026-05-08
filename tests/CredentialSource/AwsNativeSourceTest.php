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

namespace Google\Auth\Tests\CredentialSource;

use Google\Auth\CredentialSource\AwsNativeSource;
use LogicException;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * @group credentialsource
 * @group credentialsource-aws
 */
class AwsNativeSourceTest extends TestCase
{
    use ProphecyTrait;

    private string $audience = '"//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/byoid-pool-php/providers/PROJECT_ID';
    private string $regionUrl = 'https://test.regional.url';
    private string $regionalCredVerificationUrl = 'https://{region}.regional.cred.verification.url';
    private string $securityCredentialsUrl = 'https://test.security.credentials.url';
    private string $imdsv2SessionTokenUrl = 'https://test.imdsv2.session.token.url';

    public function testGetRegionFromUrl()
    {
        $httpHandler = function (RequestInterface $request): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals($this->regionUrl, (string) $request->getUri());

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn('us-east-2b');
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        $region = AwsNativeSource::getRegionFromUrl($httpHandler, $this->regionUrl, []);
        $this->assertEquals('us-east-2', $region);
    }

    /** @runInSeparateProcess */
    public function testGetRegionFromEnv()
    {
        // Without any environment variables set, getRegionFromEnv should return null
        $this->assertNull(AwsNativeSource::getRegionFromEnv());

        // Requires AWS_REGION or AWS_DEFAULT_REGION to be set
        putenv('AWS_REGION=aws-region');
        $this->assertEquals('aws-region', AwsNativeSource::getRegionFromEnv());

        // Setting the default region does not hvae an effect
        putenv('AWS_DEFAULT_REGION=aws-default-region');
        $this->assertEquals('aws-region', AwsNativeSource::getRegionFromEnv());

        // Unsetting the AWS_REGION uses AWS_DEFAULT_REGION instead
        putenv('AWS_REGION=');
        $this->assertEquals('aws-default-region', AwsNativeSource::getRegionFromEnv());
    }

    public function testGetRoleName()
    {
        $httpHandler = function (RequestInterface $request): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals($this->securityCredentialsUrl, (string) $request->getUri());

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn('expected-role-name');
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        $roleName = AwsNativeSource::getRoleName($httpHandler, $this->securityCredentialsUrl, []);

        $this->assertEquals('expected-role-name', $roleName);
    }

    public function testGetImdsV2SessionToken()
    {
        $imdsV2Url = 'http://some-metadata-url/latest/api/token';
        $httpHandler = function (RequestInterface $request) use ($imdsV2Url): ResponseInterface {
            $this->assertEquals('PUT', $request->getMethod());
            $this->assertEquals($imdsV2Url, (string) $request->getUri());
            $this->assertEquals('21600', $request->getHeaderLine('X-aws-ec2-metadata-token-ttl-seconds'));

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn('expected-aws-token');
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        $roleName = AwsNativeSource::getImdsV2SessionToken($imdsV2Url, $httpHandler);

        $this->assertEquals('expected-aws-token', $roleName);
    }

    public function testGetSigningVarsFromUrl()
    {
        $httpHandler = function (RequestInterface $request): ResponseInterface {
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
            $httpHandler,
            $this->securityCredentialsUrl,
            'test-role-name',
            []
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
        putenv('AWS_ACCESS_KEY_ID=expected-access-key-id');
        putenv('AWS_SECRET_ACCESS_KEY=expected-secret-access-key');

        $signingVars = AwsNativeSource::getSigningVarsFromEnv();

        $this->assertEquals('expected-access-key-id', $signingVars[0]);
        $this->assertEquals('expected-secret-access-key', $signingVars[1]);
        $this->assertNull($signingVars[2]);

        // AWS_SESSION_TOKEN is optional
        putenv('AWS_SESSION_TOKEN=expected-session-token');

        $signingVars = AwsNativeSource::getSigningVarsFromEnv();
        $this->assertEquals('expected-access-key-id', $signingVars[0]);
        $this->assertEquals('expected-secret-access-key', $signingVars[1]);
        $this->assertEquals('expected-session-token', $signingVars[2]);
    }

    public function testGetSignedRequestHeaders()
    {
        $region = 'us-east-2';
        $host = 'sts.us-east-2.amazonaws.com';
        $accessKeyId = 'expected-access-key-id';
        $secretAccessKey = 'expected-secret-access-key';
        $securityToken = null;
        $headers = AwsNativeSource::getSignedRequestHeaders(
            $host,
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
            '/sts/aws4_request, SignedHeaders=host;x-amz-date, ',
            $headers['Authorization']
        );
        $this->assertStringContainsString(
            ', Signature=',
            $headers['Authorization']
        );

        $securityToken = 'extected-security-token';
        $headers = AwsNativeSource::getSignedRequestHeaders(
            $region,
            $host,
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
            '/sts/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, ',
            $headers['Authorization']
        );
        $this->assertStringContainsString(
            ', Signature=',
            $headers['Authorization']
        );
    }

    public function testFetchSubjectTokenWithoutSecurityCredentialsUrlOrEnvThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'Unable to get credentials from ENV or container credentials, and no security credentials URL provided'
        );

        $aws = new AwsNativeSource(
            $this->audience,
            $this->regionUrl,
            $this->regionalCredVerificationUrl,
        );
        $httpHandler = function (RequestInterface $request): ResponseInterface {
            // Mock response from AWS Metadata Server
            $awsTokenBody = $this->prophesize(StreamInterface::class);
            $awsTokenBody->__toString()->willReturn('aws-token');
            $awsTokenResponse = $this->prophesize(ResponseInterface::class);
            $awsTokenResponse->getBody()->willReturn($awsTokenBody->reveal());
            return $awsTokenResponse->reveal();
        };
        $aws->fetchSubjectToken($httpHandler);
    }

    /** @runInSeparateProcess */
    public function testGetSigningVarsFromContainerCredentialsReturnsNullWhenEnvNotSet()
    {
        // Neither AWS_CONTAINER_CREDENTIALS_RELATIVE_URI nor _FULL_URI is set.
        $httpHandler = function (RequestInterface $request): ResponseInterface {
            throw new \LogicException('HTTP handler should not be invoked when no container credentials env is set.');
        };

        $this->assertNull(
            AwsNativeSource::getSigningVarsFromContainerCredentials($httpHandler)
        );
    }

    /** @runInSeparateProcess */
    public function testGetSigningVarsFromContainerCredentialsRelativeUri()
    {
        putenv('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/abcdef');

        $httpHandler = function (RequestInterface $request): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals(
                'http://169.254.170.2/v2/credentials/abcdef',
                (string) $request->getUri()
            );
            $this->assertFalse($request->hasHeader('Authorization'));

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

        $signingVars = AwsNativeSource::getSigningVarsFromContainerCredentials($httpHandler);

        $this->assertEquals('expected-access-key-id', $signingVars[0]);
        $this->assertEquals('expected-secret-access-key', $signingVars[1]);
        $this->assertEquals('expected-token', $signingVars[2]);
    }

    /** @runInSeparateProcess */
    public function testGetSigningVarsFromContainerCredentialsFullUriWithAuthToken()
    {
        $fullUri = 'http://eks-pod-identity.example/credentials';
        putenv('AWS_CONTAINER_CREDENTIALS_FULL_URI=' . $fullUri);
        putenv('AWS_CONTAINER_AUTHORIZATION_TOKEN=expected-bearer-token');

        $httpHandler = function (RequestInterface $request) use ($fullUri): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals($fullUri, (string) $request->getUri());
            $this->assertEquals('expected-bearer-token', $request->getHeaderLine('Authorization'));

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn(json_encode([
                'AccessKeyId' => 'full-access-key-id',
                'SecretAccessKey' => 'full-secret-access-key',
                // Token is optional in the response (e.g. long-lived creds).
            ]));
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        $signingVars = AwsNativeSource::getSigningVarsFromContainerCredentials($httpHandler);

        $this->assertEquals('full-access-key-id', $signingVars[0]);
        $this->assertEquals('full-secret-access-key', $signingVars[1]);
        $this->assertNull($signingVars[2]);
    }

    /** @runInSeparateProcess */
    public function testFetchSubjectTokenFromContainerCredentials()
    {
        // Simulate ECS Fargate: AWS_ACCESS_KEY_ID is unset but
        // AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is provided. fetchSubjectToken
        // should fall through to the container credentials endpoint instead of
        // throwing or hitting the (unconfigured) securityCredentialsUrl.
        putenv('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/task-role');

        $aws = new AwsNativeSource(
            $this->audience,
            $this->regionUrl,
            $this->regionalCredVerificationUrl,
        );

        // Mock response from container credentials endpoint
        $containerBody = $this->prophesize(StreamInterface::class);
        $containerBody->__toString()->willReturn(json_encode([
            'AccessKeyId' => 'container-access-key-id',
            'SecretAccessKey' => 'container-secret-access-key',
            'Token' => 'container-session-token',
        ]));
        $containerResponse = $this->prophesize(ResponseInterface::class);
        $containerResponse->getBody()->willReturn($containerBody->reveal());

        // Mock response from Region URL
        $regionBody = $this->prophesize(StreamInterface::class);
        $regionBody->__toString()->willReturn('us-east-2b');
        $regionResponse = $this->prophesize(ResponseInterface::class);
        $regionResponse->getBody()->willReturn($regionBody->reveal());

        $requestCount = 0;
        $httpHandler = function (RequestInterface $request) use (
            $containerResponse,
            $regionResponse,
            &$requestCount
        ): ResponseInterface {
            $requestCount++;
            switch ($requestCount) {
                case 1:
                    $this->assertEquals(
                        'http://169.254.170.2/v2/credentials/task-role',
                        (string) $request->getUri()
                    );
                    return $containerResponse->reveal();
                case 2:
                    return $regionResponse->reveal();
            }
            throw new \Exception('Unexpected request');
        };

        $subjectToken = $aws->fetchSubjectToken($httpHandler);
        $unserializedToken = json_decode(urldecode($subjectToken), true);
        $this->assertArrayHasKey('headers', $unserializedToken);
        $this->assertArrayHasKey('method', $unserializedToken);
        $this->assertArrayHasKey('url', $unserializedToken);

        // Sanity check: the SigV4 Authorization header must reference the
        // access key fetched from the container credentials endpoint.
        $authHeader = '';
        foreach ($unserializedToken['headers'] as $header) {
            if ($header['key'] === 'Authorization') {
                $authHeader = $header['value'];
                break;
            }
        }
        $this->assertStringContainsString(
            'Credential=container-access-key-id/',
            $authHeader
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testFetchSubjectTokenFromEnv()
    {
        $aws = new AwsNativeSource(
            $this->audience,
            $this->regionUrl,
            $this->regionalCredVerificationUrl,
        );

        // Set minimum number of environment variables required
        putenv('AWS_ACCESS_KEY_ID=expected-access-key-id');
        putenv('AWS_SECRET_ACCESS_KEY=expected-secret-access-key');

        // Mock response from AWS Metadata Server
        $awsTokenBody = $this->prophesize(StreamInterface::class);
        $awsTokenBody->__toString()->willReturn('aws-token');
        $awsTokenResponse = $this->prophesize(ResponseInterface::class);
        $awsTokenResponse->getBody()->willReturn($awsTokenBody->reveal());

        // Mock response from Region URL
        $regionBody = $this->prophesize(StreamInterface::class);
        $regionBody->__toString()->willReturn('us-east-2b');
        $regionResponse = $this->prophesize(ResponseInterface::class);
        $regionResponse->getBody()->willReturn($regionBody->reveal());

        $requestCount = 0;
        $httpHandler = function (RequestInterface $request) use (
            $awsTokenResponse,
            $regionResponse,
            &$requestCount
        ): ResponseInterface {
            $requestCount++;
            switch ($requestCount) {
                case 1: return $awsTokenResponse->reveal();
                case 2: return $regionResponse->reveal();
            }
            throw new \Exception('Unexpected request');
        };

        $subjectToken = $aws->fetchSubjectToken($httpHandler);
        $unserializedToken = json_decode(urldecode($subjectToken), true);
        $this->assertArrayHasKey('headers', $unserializedToken);
        $this->assertArrayHasKey('method', $unserializedToken);
        $this->assertArrayHasKey('url', $unserializedToken);
    }

    public function testFetchSubjectTokenFromUrl()
    {
        $aws = new AwsNativeSource(
            $this->audience,
            $this->regionUrl,
            $this->regionalCredVerificationUrl,
            $this->securityCredentialsUrl,
            $this->imdsv2SessionTokenUrl,
        );

        // Mock response from AWS Metadata Server
        $awsTokenBody = $this->prophesize(StreamInterface::class);
        $awsTokenBody->__toString()->willReturn('aws-token');
        $awsTokenResponse = $this->prophesize(ResponseInterface::class);
        $awsTokenResponse->getBody()->willReturn($awsTokenBody->reveal());

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

        $requestCount = 0;
        $httpHandler = function (RequestInterface $request) use (
            $awsTokenResponse,
            $roleResponse,
            $securityCredentialsResponse,
            $regionResponse,
            &$requestCount
        ): ResponseInterface {
            $requestCount++;
            switch ($requestCount) {
                case 1: return $awsTokenResponse->reveal();
                case 2: return $roleResponse->reveal();
                case 3: return $securityCredentialsResponse->reveal();
                case 4: return $regionResponse->reveal();
            }
            throw new \Exception('Unexpected request');
        };

        $subjectToken = $aws->fetchSubjectToken($httpHandler);
        $unserializedToken = json_decode(urldecode($subjectToken), true);
        $this->assertArrayHasKey('headers', $unserializedToken);
        $this->assertArrayHasKey('method', $unserializedToken);
        $this->assertArrayHasKey('url', $unserializedToken);
    }
}
