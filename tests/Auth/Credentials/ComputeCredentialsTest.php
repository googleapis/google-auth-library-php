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

use Google\Auth\Credentials\ComputeCredentials;
use Google\Jwt\ClientInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * @group credentials
 * @group credentials-compute
 *
 * @internal
 * @covers \Google\Auth\Credentials\ComputeCredentials
 */
class ComputeCredentialsTest extends TestCase
{
    public function testFetchAuthTokenThrowsExceptionIfNotOnCompute()
    {
        $this->expectException('GuzzleHttp\Exception\ServerException');

        // simulate retry attempts by returning multiple 500s
        $httpClient = httpClientWithResponses([new Response(500)]);
        $compute = new ComputeCredentials(['httpClient' => $httpClient]);
        $this->assertEquals([], $compute->fetchAuthToken());
    }

    public function testFetchAuthTokenShouldFailIfResponseIsNotJson()
    {
        $this->expectException('Exception');
        $this->expectExceptionMessage('Invalid JSON response');

        $notJson = '{"foo": , this is cannot be passed as json" "bar"}';
        $httpClient = httpClientWithResponses([
            new Response(200, [], $notJson),
        ]);
        $compute = new ComputeCredentials(['httpClient' => $httpClient]);
        $compute->fetchAuthToken();
    }

    public function testFetchAuthTokenShouldReturnTokenInfo()
    {
        $wantedToken = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
            'expires_at' => time() + 57,
        ];
        $jsonTokens = json_encode($wantedToken);
        $httpClient = httpClientWithResponses([
            new Response(200, [], $jsonTokens),
        ]);

        $compute = new ComputeCredentials(['httpClient' => $httpClient]);
        $this->assertEquals($wantedToken, $compute->fetchAuthToken());
    }

    public function testFetchAuthTokenShouldBeIdTokenWhenTargetAudienceIsSet()
    {
        $expected = 'idtoken12345';
        $httpClient = httpClientFromCallable(
            function ($request) use ($expected) {
                $this->assertEquals(
                    '/computeMetadata/v1/instance/service-accounts/default/identity',
                    $request->getUri()->getPath()
                );
                $this->assertEquals(
                    'audience=a-target-audience',
                    $request->getUri()->getQuery()
                );

                return new Response(200, [], $expected);
            }
        );

        $jwtClient = $this->prophesize(ClientInterface::class);
        $jwtClient->getExpirationWithoutVerification($expected)
            ->willReturn(12345)
        ;

        $compute = new ComputeCredentials([
            'httpClient' => $httpClient,
            'jwtClient' => $jwtClient->reveal(),
            'targetAudience' => 'a-target-audience',
        ]);
        $this->assertEquals([
            'id_token' => $expected,
            'expires_at' => 12345,
        ], $compute->fetchAuthToken());
    }

    public function testSettingBothScopeAndTargetAudienceThrowsException()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('Scope and targetAudience cannot both be supplied');
        $compute = new ComputeCredentials([
            'scope' => 'a-scope',
            'targetAudience' => 'a-target-audience',
        ]);
    }

    /**
     * @dataProvider scopes
     *
     * @param mixed $scope
     * @param mixed $expected
     */
    public function testFetchAuthTokenCustomScope($scope, $expected)
    {
        $uri = null;
        $httpClient = httpClientFromCallable(function ($request) use (&$uri) {
            $uri = $request->getUri();

            return new Response(200, [], '{"expires_in": 0}');
        });

        $compute = new ComputeCredentials([
            'scope' => $scope,
            'httpClient' => $httpClient,
        ]);

        $compute->fetchAuthToken();
        parse_str($uri->getQuery(), $query);

        $this->assertArrayHasKey('scopes', $query);
        $this->assertEquals($expected, $query['scopes']);
    }

    public function scopes()
    {
        return [
            ['foobar', 'foobar'],
            [['foobar'], 'foobar'],
            ['hello world', 'hello,world'],
            [['hello', 'world'], 'hello,world'],
        ];
    }

    public function testGetClientName()
    {
        $expected = 'foobar';

        $httpClient = httpClientWithResponses([
            new Response(200, [], $expected),
            new Response(200, [], 'notexpected'),
        ]);

        $compute = new ComputeCredentials(['httpClient' => $httpClient]);
        $this->assertEquals($expected, $compute->getClientEmail($httpClient));

        // call again to test cached value
        $this->assertEquals($expected, $compute->getClientEmail($httpClient));
    }

    public function testGetClientNameShouldThrowExceptionIfNotOnCompute()
    {
        $this->expectException('GuzzleHttp\Exception\ServerException');

        // simulate retry attempts by returning multiple 500s
        $httpClient = httpClientWithResponses([new Response(500)]);

        $compute = new ComputeCredentials(['httpClient' => $httpClient]);
        $this->assertEquals('', $compute->getClientEmail());
    }

    public function testSignBlob()
    {
        $expectedEmail = 'test@test.com';
        $expectedAccessToken = 'token';
        $expectedSignature = 'foobar';
        $token = [
            'access_token' => $expectedAccessToken,
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];

        $httpClient = httpClientWithResponses([
            new Response(200, [], json_encode($token)),
            new Response(200, [], $expectedEmail),
            new Response(200, [], json_encode(['signedBlob' => $expectedSignature])),
        ]);

        $compute = new ComputeCredentials([
            'httpClient' => $httpClient,
        ]);
        $signature = $compute->signBlob('string-to-sign');
        $this->assertEquals($expectedSignature, $signature);
    }

    public function testSignBlobFromCache()
    {
        $expectedEmail = 'test@test.com';
        $expectedAccessToken = 'token';
        $notExpectedAccessToken = 'othertoken';
        $expectedSignature = 'foobar';
        $token1 = [
            'access_token' => $expectedAccessToken,
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];

        $httpClient = httpClientWithResponses([
            new Response(200, [], json_encode($token1)),
            new Response(200, [], $expectedEmail),
            new Response(200, [], json_encode(['signedBlob' => $expectedSignature])),
        ]);

        $compute = new ComputeCredentials([
            'httpClient' => $httpClient,
        ]);
        // cache a token
        $compute->fetchAuthToken();

        $signature = $compute->signBlob('string-to-sign');
        $this->assertEquals($expectedSignature, $signature);
    }

    public function testGetProjectId()
    {
        $expected = 'foobar';

        $httpClient = httpClientWithResponses([
            new Response(200, [], $expected),
            new Response(200, [], 'notexpected'),
        ]);

        $compute = new ComputeCredentials([
            'httpClient' => $httpClient,
        ]);
        $this->assertEquals($expected, $compute->getProjectId());

        // call again to test cached value
        $this->assertEquals($expected, $compute->getProjectId());
    }

    public function testGetProjectIdThrowsExceptionIfNotOnCompute()
    {
        $this->expectException('GuzzleHttp\Exception\ServerException');

        // simulate retry attempts by returning multiple 500s
        $httpClient = httpClientWithResponses([new Response(500)]);

        $compute = new ComputeCredentials([
            'httpClient' => $httpClient,
        ]);
        $this->assertNull($compute->getProjectId());
    }

    public function testGetTokenUriWithServiceAccountIdentity()
    {
        $expectedToken = [
            'access_token' => '123',
            'expires_in' => 1000,
        ];
        $httpClient = httpClientFromCallable(
            function ($request) use ($expectedToken) {
                $this->assertEquals(
                    '/computeMetadata/v1/instance/service-accounts/foo/token',
                    $request->getUri()->getPath()
                );

                return new Response(200, [], json_encode($expectedToken));
            }
        );
        $compute = new ComputeCredentials([
            'serviceAccountIdentity' => 'foo',
            'httpClient' => $httpClient,
        ]);
        $token = $compute->fetchAuthToken();
        $this->assertEquals($expectedToken['access_token'], $token['access_token']);
    }

    public function testGetAccessTokenWithServiceAccountIdentity()
    {
        $expected = [
            'access_token' => 'token12345',
            'expires_in' => 123,
        ];
        $httpClient = httpClientFromCallable(function ($request) use ($expected) {
            $this->assertEquals(
                '/computeMetadata/v1/instance/service-accounts/foo/token',
                $request->getUri()->getPath()
            );
            $this->assertEquals('', $request->getUri()->getQuery());

            return new Response(200, [], json_encode($expected));
        });

        $compute = new ComputeCredentials([
            'serviceAccountIdentity' => 'foo',
            'httpClient' => $httpClient,
        ]);
        $this->assertEquals(
            $expected['access_token'],
            $compute->fetchAuthToken()['access_token']
        );
    }

    public function testGetIdTokenWithServiceAccountIdentity()
    {
        $expected = 'idtoken12345';
        $httpClient = httpClientFromCallable(function ($request) use ($expected) {
            $this->assertEquals(
                '/computeMetadata/v1/instance/service-accounts/foo/identity',
                $request->getUri()->getPath()
            );
            $this->assertEquals(
                'audience=a-target-audience',
                $request->getUri()->getQuery()
            );

            return new Response(200, [], $expected);
        });

        $jwtClient = $this->prophesize(ClientInterface::class);
        $jwtClient->getExpirationWithoutVerification($expected)
            ->willReturn(12345)
        ;

        $compute = new ComputeCredentials([
            'httpClient' => $httpClient,
            'targetAudience' => 'a-target-audience',
            'serviceAccountIdentity' => 'foo',
            'jwtClient' => $jwtClient->reveal(),
        ]);
        $this->assertEquals(
            [
                'id_token' => $expected,
                'expires_at' => 12345,
            ],
            $compute->fetchAuthToken()
        );
    }

    public function testGetClientEmailWithServiceAccountIdentity()
    {
        $expected = 'clientemail';
        $httpClient = httpClientFromCallable(function ($request) use ($expected) {
            $this->assertEquals(
                '/computeMetadata/v1/instance/service-accounts/foo/email',
                $request->getUri()->getPath()
            );

            return new Response(200, [], $expected);
        });
        $compute = new ComputeCredentials([
            'httpClient' => $httpClient,
            'serviceAccountIdentity' => 'foo',
        ]);
        $this->assertEquals($expected, $compute->getClientEmail());
    }
}
