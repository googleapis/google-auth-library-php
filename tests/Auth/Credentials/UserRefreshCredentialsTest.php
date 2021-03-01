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

use Google\Auth\Credentials\UserRefreshCredentials;
use Google\Auth\OAuth2;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @covers \Google\Auth\Credentials\UserRefreshCredentials
 */
class UserRefreshCredentialsTest extends TestCase
{
    private $testJson = [
        'client_id' => 'client123',
        'client_secret' => 'clientSecret123',
        'refresh_token' => 'refreshToken123',
        'type' => 'authorized_user',
    ];

    public function testCacheKeyShouldBeTheSameAsOAuth2WithTheSameScope()
    {
        $scope = ['scope/1', 'scope/2'];
        $credentials = new UserRefreshCredentials($this->testJson, [
            'scope' => $scope,
        ]);

        $reflection = new \ReflectionClass($credentials);
        $method = $reflection->getMethod('getCacheKey');
        $method->setAccessible(true);
        $cacheKey = $method->invoke($credentials);

        $o = new OAuth2(['scope' => $scope]);
        $this->assertSame(
            $this->testJson['client_id'] . ':' . $o->getCacheKey(),
            $cacheKey
        );
    }

    public function testShouldFailIfScopeIsNotAValidType()
    {
        $this->expectException(InvalidArgumentException::class);

        $notAnArrayOrString = new \stdClass();
        $credentials = new UserRefreshCredentials($this->testJson, [
            'scope' => $notAnArrayOrString,
        ]);
    }

    public function testShouldFailIfJsonDoesNotHaveClientSecret()
    {
        $this->expectException(InvalidArgumentException::class);

        unset($this->testJson['client_secret']);
        $scope = ['scope/1', 'scope/2'];
        $credentials = new UserRefreshCredentials($this->testJson, [
            'scope' => $scope,
        ]);
    }

    public function testShouldFailIfJsonDoesNotHaveRefreshToken()
    {
        $this->expectException(InvalidArgumentException::class);

        unset($this->testJson['refresh_token']);
        $scope = ['scope/1', 'scope/2'];
        $credentials = new UserRefreshCredentials($this->testJson, [
            'scope' => $scope,
        ]);
    }

    public function testShouldFailIfJsonDoesNotHaveClientId()
    {
        $this->expectException(InvalidArgumentException::class);

        unset($this->testJson['client_id']);
        $scope = ['scope/1', 'scope/2'];
        $credentials = new UserRefreshCredentials($this->testJson, [
            'scope' => $scope,
        ]);
    }

    public function testFailsToInitalizeFromANonExistentFile()
    {
        $this->expectException(InvalidArgumentException::class);
        $keyFile = __DIR__ . '/../fixtures/does-not-exist-private.json';
        new UserRefreshCredentials($keyFile, [
            'scope' => 'scope/1',
        ]);
    }

    public function testInitalizeFromAFile()
    {
        $keyFile = __DIR__ . '/../fixtures/client_credentials.json';
        $credentials = new UserRefreshCredentials($keyFile, [
            'scope' => 'scope/1',
        ]);
        $this->assertNotNull($credentials);
    }

    public function testFailsToInitializeFromInvalidJsonData()
    {
        $this->expectException(LogicException::class);

        $tmp = tmpfile();
        fwrite($tmp, '{');

        $path = stream_get_meta_data($tmp)['uri'];

        try {
            new UserRefreshCredentials($path, [
                'scope' => 'scope/1',
            ]);
        } finally {
            fclose($tmp);
        }
    }

    public function testFailsOnClientErrors()
    {
        $this->expectException(ClientException::class);

        $scope = ['scope/1', 'scope/2'];
        $httpClient = httpClientWithResponses([
            new Response(400),
        ]);
        $credentials = new UserRefreshCredentials($this->testJson, [
            'scope' => $scope,
            'httpClient' => $httpClient,
        ]);
        $credentials->fetchAuthToken();
    }

    public function testFailsOnServerErrors()
    {
        $this->expectException(ServerException::class);

        $scope = ['scope/1', 'scope/2'];
        $httpClient = httpClientWithResponses([
            new Response(500),
        ]);
        $credentials = new UserRefreshCredentials($this->testJson, [
            'scope' => $scope,
            'httpClient' => $httpClient,
        ]);
        $credentials->fetchAuthToken();
    }

    public function testCanFetchCredsOK()
    {
        $jsonText = json_encode($this->testJson);
        $scope = ['scope/1', 'scope/2'];
        $httpClient = httpClientWithResponses([
            new Response(200, [], $jsonText),
        ]);
        $credentials = new UserRefreshCredentials($this->testJson, [
            'scope' => $scope,
            'httpClient' => $httpClient,
        ]);
        $tokens = $credentials->fetchAuthToken($httpClient);
        $this->assertEquals($this->testJson, $tokens);
    }

    public function testGetQuotaProject()
    {
        $keyFile = __DIR__ . '/../fixtures/client_credentials.json';
        $credentials = new UserRefreshCredentials($keyFile, [
            'scope' => 'a-scope',
        ]);
        $this->assertEquals(
            'test_quota_project',
            $credentials->getQuotaProject()
        );
    }
}
