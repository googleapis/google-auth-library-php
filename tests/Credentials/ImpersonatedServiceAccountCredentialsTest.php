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
use Google\Auth\Credentials\UserRefreshCredentials;
use Google\Auth\Middleware\AuthTokenMiddleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use LogicException;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class ImpersonatedServiceAccountCredentialsTest extends TestCase
{
    use ProphecyTrait;

    // Creates a standard JSON auth object for testing.
    private function createISACTestJson()
    {
        return json_decode(file_get_contents(__DIR__ . '/../fixtures3/impersonated_service_account_credentials.json'), true);
    }

    public function testGetServiceAccountNameEmail()
    {
        $testJson = $this->createISACTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sa = new ImpersonatedServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertEquals('test@test-project.iam.gserviceaccount.com', $sa->getClientName());
    }

    public function testGetServiceAccountNameID()
    {
        $testJson = $this->createISACTestJson();
        $testJson['service_account_impersonation_url'] = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/1234567890987654321:generateAccessToken';
        $scope = ['scope/1', 'scope/2'];
        $sa = new ImpersonatedServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertEquals('1234567890987654321', $sa->getClientName());
    }

    public function testErrorCredentials()
    {
        $testJson = $this->createISACTestJson();
        $scope = ['scope/1', 'scope/2'];
        $this->expectException(LogicException::class);
        new ImpersonatedServiceAccountCredentials($scope, $testJson['source_credentials']);
    }

    public function testGetIdToken()
    {
        $testJson = $this->createISACTestJson();
        $targetAudience = '123@456.com';
        $creds = new ImpersonatedServiceAccountCredentials(null, $testJson, null, $targetAudience);

        $requestCount = 0;
        // getting an id token will take two requests
        $httpHandler = function (RequestInterface $request) use (&$requestCount, $creds) {
            $impersonatedServiceAccount = $creds->getClientName();

            $responseBody = '';
            switch (++$requestCount) {
                case 1: // the call to swap the refresh token for an access token
                    $this->assertEquals(UserRefreshCredentials::TOKEN_CREDENTIAL_URI, (string) $request->getUri());
                    $responseBody = '{"access_token":"this is an access token"}';
                    break;

                case 2: // the call to swap the access token for an id token
                    $this->assertEquals("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{$impersonatedServiceAccount}:generateIdToken", (string) $request->getUri());
                    $authHeader = $request->getHeader('authorization');
                    $this->assertCount(1, $authHeader);
                    $this->assertEquals('Bearer this is an access token', $authHeader[0]);
                    $responseBody = '{"token": "this is the id token"}';
                    break;
            }

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn($responseBody);

            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());
            $response->hasHeader('Content-Type')->willReturn(true);
            $response->getHeaderLine('Content-Type')->willReturn('application/json');

            if ($requestCount === 2) {
                $response->hasHeader('Content-Type')->willReturn(false);
            }

            return $response->reveal();
        };

        $creds->fetchAuthToken($httpHandler);
        // any checks on the result are futile as they have been coded above
    }
    public function testCanBeUsedInAuthTokenMiddlewareWhenAnAudienceIsGiven()
    {
        $targetAudience = '123@456.com';
        $jsonKey = $this->createISACTestJson();
        $credentials = new ImpersonatedServiceAccountCredentials(null, $jsonKey, null, $targetAudience);

        // this handler is for the middleware constructor, which will pass it to the ISAC to fetch tokens
        $httpHandler = getHandler([
            new Response(200, ['Content-Type' => 'application/json'], '{"access_token":"this.is.an.access.token"}'),
            new Response(200, ['Content-Type' => 'application/json'], '{"token":"this.is.an.id.token"}'),
        ]);
        $middleware = new AuthTokenMiddleware($credentials, $httpHandler);

        // this handler is the actual handler that makes the authenticated request
        $httpHandler = function (RequestInterface $request) use (&$requestCount) {
            $this->assertTrue($request->hasHeader('authorization'));
            $authHeader = $request->getHeader('authorization');
            $this->assertCount(1, $authHeader);
            $this->assertEquals('Bearer this.is.an.id.token', $authHeader[0]);
        };

        $middleware($httpHandler)(
            new Request('GET', 'https://www.google.com'),
            ['auth' => 'google_auth']
        );
    }
}
