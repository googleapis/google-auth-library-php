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

use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\OAuth2;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @covers \Google\Auth\Credentials\ServiceAccountCredentials
 */
class ServiceAccountCredentialsTest extends TestCase
{
    private static $privateKey;
    private $testJson = [
        'private_key_id' => 'key123',
        'private_key' => 'privatekey',
        'client_email' => 'test@example.com',
        'client_id' => 'client123',
        'type' => 'service_account',
        'project_id' => 'example_project',
    ];

    public static function setUpBeforeClass(): void
    {
        self::$privateKey = file_get_contents(
            __DIR__ . '/../fixtures/private.pem'
        );
    }

    public function testShouldBeTheSameAsOAuth2WithTheSameScope()
    {
        $scope = ['scope/1', 'scope/2'];
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => $scope,
        ]);

        $reflection = new \ReflectionClass($credentials);
        $method = $reflection->getMethod('getCacheKey');
        $method->setAccessible(true);
        $cacheKey = $method->invoke($credentials);

        $o = new OAuth2(['scope' => $scope]);
        $this->assertEquals(
            $this->testJson['client_email'] . ':' . $o->getCacheKey(),
            $cacheKey
        );
    }

    public function testShouldBeTheSameAsOAuth2WithTheSameScopeWithSub()
    {
        $scope = ['scope/1', 'scope/2'];
        $sub = 'sub123';
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => $scope,
            'subject' => $sub,
        ]);

        $reflection = new \ReflectionClass($credentials);
        $method = $reflection->getMethod('getCacheKey');
        $method->setAccessible(true);
        $cacheKey = $method->invoke($credentials);

        $o = new OAuth2(['scope' => $scope]);
        $this->assertEquals(
            $this->testJson['client_email'] . ':' . $o->getCacheKey() . ':' . $sub,
            $cacheKey
        );
    }

    public function testShouldFailIfScopeIsNotAValidType()
    {
        $this->expectException(InvalidArgumentException::class);

        $notAnArrayOrString = new \stdClass();
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => $notAnArrayOrString,
        ]);
    }

    public function testShouldFailIfJsonDoesNotHaveClientEmail()
    {
        $this->expectException(InvalidArgumentException::class);

        unset($this->testJson['client_email']);
        $scope = ['scope/1', 'scope/2'];
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => $scope,
        ]);
    }

    public function testShouldFailIfJsonDoesNotHavePrivateKey()
    {
        $this->expectException(InvalidArgumentException::class);

        unset($this->testJson['private_key']);
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => ['scope/1', 'scope/2'],
        ]);
    }

    public function testFailsToInitalizeFromANonExistentFile()
    {
        $this->expectException(InvalidArgumentException::class);

        $keyFile = __DIR__ . '/../fixtures' . '/does-not-exist-private.json';
        $credentials = new ServiceAccountCredentials($keyFile, [
            'scope' => ['scope/1', 'scope/2'],
        ]);
    }

    public function testInitalizeFromAFile()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        $credentials = new ServiceAccountCredentials($keyFile, [
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
            new ServiceAccountCredentials($path, [
                'scope' => 'scope/1',
            ]);
        } finally {
            fclose($tmp);
        }
    }

    public function testFailsOnClientErrors()
    {
        $this->expectException(ClientException::class);
        $this->testJson['private_key'] = self::$privateKey;
        $scope = ['scope/1', 'scope/2'];
        $httpClient = httpClientWithResponses([
            new Response(400),
        ]);
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => $scope,
            'httpClient' => $httpClient,
        ]);
        $credentials->fetchAuthToken();
    }

    public function testFailsOnServerErrors()
    {
        $this->expectException(ServerException::class);
        $this->testJson['private_key'] = self::$privateKey;
        $scope = ['scope/1', 'scope/2'];
        $httpClient = httpClientWithResponses([
            new Response(500),
        ]);
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => $scope,
            'httpClient' => $httpClient,
        ]);
        $credentials->fetchAuthToken();
    }

    public function testCanFetchCredsOK()
    {
        $this->testJson['private_key'] = self::$privateKey;
        $testJsonText = json_encode($this->testJson);
        $httpClient = httpClientWithResponses([
            new Response(200, [], $testJsonText),
        ]);
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => ['scope/1', 'scope/2'],
            'httpClient' => $httpClient,
        ]);
        $tokens = $credentials->fetchAuthToken();
        $this->assertEquals($this->testJson, $tokens);
    }

    public function testGetRequestMetadata()
    {
        $this->testJson['private_key'] = self::$privateKey;
        $scope = ['scope/1', 'scope/2'];
        $access_token = 'accessToken123';
        $responseText = json_encode(['access_token' => $access_token]);
        $httpClient = httpClientWithResponses([
            new Response(200, [], $responseText),
        ]);
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => $scope,
            'httpClient' => $httpClient,
        ]);
        $metadata = $credentials->getRequestMetadata();
        $this->assertIsArray($metadata);

        $this->assertArrayHasKey('Authorization', $metadata);
        $this->assertEquals(
            $metadata['Authorization'],
            'Bearer ' . $access_token
        );
    }

    public function testShouldBeIdTokenWhenTargetAudienceIsSet()
    {
        $this->testJson['private_key'] = self::$privateKey;
        $expectedToken = ['id_token' => 'idtoken12345'];
        $timesCalled = 0;
        $httpClient = httpClientFromCallable(
            function ($request) use (&$timesCalled, $expectedToken) {
                ++$timesCalled;
                parse_str($request->getBody(), $post);
                $this->assertArrayHasKey('assertion', $post);
                list($header, $payload, $sig) = explode('.', $post['assertion']);
                $jwtParams = json_decode(base64_decode($payload), true);
                $this->assertArrayHasKey('target_audience', $jwtParams);
                $this->assertEquals('a target audience', $jwtParams['target_audience']);

                return new Response(200, [], json_encode($expectedToken));
            }
        );
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'targetAudience' => 'a target audience',
            'httpClient' => $httpClient,
        ]);
        $this->assertEquals($expectedToken, $credentials->fetchAuthToken());
        $this->assertEquals(1, $timesCalled);
    }

    public function testSettingBothScopeAndTargetAudienceThrowsException()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Scope and targetAudience cannot both be supplied');

        $this->testJson['private_key'] = self::$privateKey;
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => 'a-scope',
            'targetAudience' => 'a-target-audience',
        ]);
    }

    public function testReturnsClientEmail()
    {
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => 'scope/1',
        ]);
        $this->assertEquals(
            $this->testJson['client_email'],
            $credentials->getClientEmail()
        );
    }

    public function testGetProjectId()
    {
        $credentials = new ServiceAccountCredentials($this->testJson, [
            'scope' => 'scope/1',
        ]);
        $this->assertEquals(
            $this->testJson['project_id'],
            $credentials->getProjectId()
        );
    }

    public function testGetQuotaProject()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        $credentials = new ServiceAccountCredentials($keyFile, [
            'scope' => 'scope/1',
        ]);
        $this->assertEquals(
            'test_quota_project',
            $credentials->getQuotaProject()
        );
    }

    public function testNoScopeUsesJwtAccess()
    {
        $this->testJson['private_key'] = self::$privateKey;

        // no scope, jwt access should be used, no outbound
        // call should be made
        $credentials = new ServiceAccountCredentials($this->testJson);

        $authUri = 'https://example.com/service';
        $metadata = $credentials->getRequestMetadata($authUri);

        $this->assertArrayHasKey('Authorization', $metadata);

        $bearer_token = $metadata['Authorization'];
        $this->assertIsString($bearer_token);
        $this->assertEquals(0, strpos($bearer_token, 'Bearer '));
        $this->assertGreaterThan(30, strlen($bearer_token));
    }

    public function testNoScopeAndNoAuthUri()
    {
        $this->testJson['private_key'] = self::$privateKey;

        // no scope, jwt access should be used, no outbound
        // call should be made
        $credentials = new ServiceAccountCredentials($this->testJson);
        $this->assertNotNull($credentials);

        $metadata = $credentials->getRequestMetadata(null);

        // no access_token is added to the metadata hash
        // but also, no error should be thrown
        $this->assertEquals([], $metadata);
    }
}
