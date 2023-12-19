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

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Google\Auth\ApplicationDefaultCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountJwtAccessCredentials;
use Google\Auth\CredentialsLoader;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

class ServiceAccountJwtAccessCredentialsTest extends TestCase
{
    private function createTestJson()
    {
        return [
            'private_key_id' => 'key123',
            'private_key' => 'privatekey',
            'client_email' => 'test@example.com',
            'client_id' => 'client123',
            'type' => 'service_account',
            'project_id' => 'example_project',
            'private_key' => file_get_contents(__DIR__ . '/../fixtures' . '/private.pem'),
        ];
    }

    public function testFailsToInitalizeFromANonExistentFile()
    {
        $this->expectException(InvalidArgumentException::class);

        $keyFile = __DIR__ . '/../fixtures' . '/does-not-exist-private.json';
        new ServiceAccountJwtAccessCredentials($keyFile);
    }

    public function testInitalizeFromAFile()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        $this->assertNotNull(
            new ServiceAccountJwtAccessCredentials($keyFile)
        );
    }

    public function testFailsToInitializeFromInvalidJsonData()
    {
        $this->expectException(LogicException::class);
        $tmp = tmpfile();
        fwrite($tmp, '{');

        $path = stream_get_meta_data($tmp)['uri'];

        try {
            new ServiceAccountJwtAccessCredentials($path);
        } catch (\Exception $e) {
            fclose($tmp);
            throw $e;
        }
    }

    public function testFailsOnMissingClientEmail()
    {
        $this->expectException(InvalidArgumentException::class);

        $testJson = $this->createTestJson();
        unset($testJson['client_email']);
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
    }

    public function testFailsOnMissingPrivateKey()
    {
        $this->expectException(InvalidArgumentException::class);

        $testJson = $this->createTestJson();
        unset($testJson['private_key']);
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
    }

    public function testFailsWithBothAudienceAndScope()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Cannot sign both audience and scope in JwtAccess');

        $scope = 'scope/1';
        $audience = 'https://example.com/service';
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials($testJson, $scope);
        $sa->updateMetadata([], $audience);
    }

    public function testCanInitializeFromJson()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
        $this->assertNotNull($sa);
    }

    public function testNoOpOnFetchAuthToken()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
        $this->assertNotNull($sa);

        $httpHandler = getHandler([
            new Response(200),
        ]);
        $result = $sa->fetchAuthToken($httpHandler); // authUri has not been set
        $this->assertNull($result);
    }

    public function testAuthUriIsNotSet()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
        $this->assertNotNull($sa);

        $update_metadata = $sa->getUpdateMetadataFunc();
        $this->assertTrue(is_callable($update_metadata));

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = ['foo' => 'bar'],
            $authUri = null
        );
        $this->assertArrayNotHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );
    }

    public function testGetLastReceivedToken()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials($testJson);
        $token = $sa->fetchAuthToken();
        $this->assertEquals($token, $sa->getLastReceivedToken());
    }

    public function testUpdateMetadataFunc()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
        $this->assertNotNull($sa);

        $update_metadata = $sa->getUpdateMetadataFunc();
        $this->assertTrue(is_callable($update_metadata));

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = ['foo' => 'bar'],
            $authUri = 'https://example.com/service'
        );
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );

        $authorization = $actual_metadata[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertTrue(is_array($authorization));

        $bearer_token = current($authorization);
        $this->assertTrue(is_string($bearer_token));
        $this->assertEquals(0, strpos($bearer_token, 'Bearer '));
        $this->assertGreaterThan(30, strlen($bearer_token));

        $actual_metadata2 = call_user_func(
            $update_metadata,
            $metadata = ['foo' => 'bar'],
            $authUri = 'https://example.com/anotherService'
        );
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata2
        );

        $authorization2 = $actual_metadata2[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertTrue(is_array($authorization2));

        $bearer_token2 = current($authorization2);
        $this->assertTrue(is_string($bearer_token2));
        $this->assertEquals(0, strpos($bearer_token2, 'Bearer '));
        $this->assertGreaterThan(30, strlen($bearer_token2));
        $this->assertNotEquals($bearer_token2, $bearer_token);
    }

    public function testNoScopeUseJwtAccess()
    {
        $testJson = $this->createTestJson();
        // no scope, jwt access should be used, no outbound
        // call should be made
        $scope = null;
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertNotNull($sa);

        $update_metadata = $sa->getUpdateMetadataFunc();
        $this->assertTrue(is_callable($update_metadata));

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = ['foo' => 'bar'],
            $authUri = 'https://example.com/service'
        );
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );

        $authorization = $actual_metadata[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertTrue(is_array($authorization));

        $bearer_token = current($authorization);
        $this->assertTrue(is_string($bearer_token));
        $this->assertEquals(0, strpos($bearer_token, 'Bearer '));
        $this->assertGreaterThan(30, strlen($bearer_token));
    }

    public function testUpdateMetadataWithScopeAndUseJwtAccessWithScopeParameter()
    {
        $testJson = $this->createTestJson();
        // jwt access should be used even when scopes are supplied, no outbound
        // call should be made
        $scope = 'scope1 scope2';
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $sa->useJwtAccessWithScope();

        $actual_metadata = $sa->updateMetadata(
            $metadata = ['foo' => 'bar'],
            $authUri = 'https://example.com/service'
        );

        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );

        $authorization = $actual_metadata[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertTrue(is_array($authorization));

        $bearer_token = current($authorization);
        $this->assertTrue(is_string($bearer_token));
        $this->assertEquals(0, strpos($bearer_token, 'Bearer '));

        // Ensure scopes are signed inside
        $token = substr($bearer_token, strlen('Bearer '));
        $this->assertEquals(2, substr_count($token, '.'));
        list($header, $payload, $sig) = explode('.', $bearer_token);
        $json = json_decode(base64_decode($payload), true);
        $this->assertTrue(is_array($json));
        $this->assertArrayHasKey('scope', $json);
        $this->assertEquals($json['scope'], $scope);
    }

    public function testUpdateMetadataWithScopeAndUseJwtAccessWithScopeParameterAndArrayScopes()
    {
        $testJson = $this->createTestJson();
        // jwt access should be used even when scopes are supplied, no outbound
        // call should be made
        $scope = ['scope1', 'scope2'];
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $sa->useJwtAccessWithScope();

        $actual_metadata = $sa->updateMetadata(
            $metadata = ['foo' => 'bar'],
            $authUri = 'https://example.com/service'
        );

        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );

        $authorization = $actual_metadata[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertTrue(is_array($authorization));

        $bearer_token = current($authorization);
        $this->assertTrue(is_string($bearer_token));
        $this->assertEquals(0, strpos($bearer_token, 'Bearer '));

        // Ensure scopes are signed inside
        $token = substr($bearer_token, strlen('Bearer '));
        $this->assertEquals(2, substr_count($token, '.'));
        list($header, $payload, $sig) = explode('.', $bearer_token);
        $json = json_decode(base64_decode($payload), true);
        $this->assertTrue(is_array($json));
        $this->assertArrayHasKey('scope', $json);
        $this->assertEquals($json['scope'], implode(' ', $scope));

        // Test last received token
        $cachedToken = $sa->getLastReceivedToken();
        $this->assertTrue(is_array($cachedToken));
        $this->assertArrayHasKey('access_token', $cachedToken);
        $this->assertEquals($token, $cachedToken['access_token']);
    }

    public function testFetchAuthTokenWithScopeAndUseJwtAccessWithScopeParameter()
    {
        $testJson = $this->createTestJson();
        // jwt access should be used even when scopes are supplied, no outbound
        // call should be made
        $scope = 'scope1 scope2';
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $sa->useJwtAccessWithScope();

        $access_token = $sa->fetchAuthToken();
        $this->assertTrue(is_array($access_token));
        $this->assertArrayHasKey('access_token', $access_token);
        $token = $access_token['access_token'];

        // Ensure scopes are signed inside
        $this->assertEquals(2, substr_count($token, '.'));
        list($header, $payload, $sig) = explode('.', $token);
        $json = json_decode(base64_decode($payload), true);
        $this->assertTrue(is_array($json));
        $this->assertArrayHasKey('scope', $json);
        $this->assertEquals($json['scope'], $scope);
    }

    public function testFetchAuthTokenWithScopeAndUseJwtAccessWithScopeParameterAndArrayScopes()
    {
        $testJson = $this->createTestJson();
        // jwt access should be used even when scopes are supplied, no outbound
        // call should be made
        $scope = ['scope1', 'scope2'];
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $sa->useJwtAccessWithScope();

        $access_token = $sa->fetchAuthToken();
        $this->assertTrue(is_array($access_token));
        $this->assertArrayHasKey('access_token', $access_token);
        $token = $access_token['access_token'];

        // Ensure scopes are signed inside
        $this->assertEquals(2, substr_count($token, '.'));
        list($header, $payload, $sig) = explode('.', $token);
        $json = json_decode(base64_decode($payload), true);
        $this->assertTrue(is_array($json));
        $this->assertArrayHasKey('scope', $json);
        $this->assertEquals($json['scope'], implode(' ', $scope));

        // Test last received token
        $cachedToken = $sa->getLastReceivedToken();
        $this->assertTrue(is_array($cachedToken));
        $this->assertArrayHasKey('access_token', $cachedToken);
        $this->assertEquals($token, $cachedToken['access_token']);
    }

    /** @runInSeparateProcess */
    public function testAccessFromApplicationDefault()
    {
        $keyFile = __DIR__ . '/../fixtures3/service_account_credentials.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $creds = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a default scope' // $defaultScope
        );
        $authUri = 'https://example.com/service';

        $metadata = $creds->updateMetadata(['foo' => 'bar'], $authUri);

        $this->assertArrayHasKey('authorization', $metadata);
        $token = str_replace('Bearer ', '', $metadata['authorization'][0]);
        $key = file_get_contents(__DIR__ . '/../fixtures3/key.pub');
        $result = JWT::decode($token, new Key($key, 'RS256'));

        $this->assertEquals($authUri, $result->aud);
    }

    public function testNoScopeAndNoAuthUri()
    {
        $testJson = $this->createTestJson();
        // no scope, jwt access should be used, no outbound
        // call should be made
        $scope = null;
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertNotNull($sa);

        $update_metadata = $sa->getUpdateMetadataFunc();
        $this->assertTrue(is_callable($update_metadata));

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = ['foo' => 'bar'],
            $authUri = null
        );
        // no access_token is added to the metadata hash
        // but also, no error should be thrown
        $this->assertTrue(is_array($actual_metadata));
        $this->assertArrayNotHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );
    }

    public function testUpdateMetadataJwtAccess()
    {
        $testJson = $this->createTestJson();
        // no scope, jwt access should be used, no outbound
        // call should be made
        $scope = null;
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertNotNull($sa);
        $metadata = $sa->updateMetadata(
            ['foo' => 'bar'],
            'https://example.com/service'
        );
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $metadata
        );

        $authorization = $metadata[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertTrue(is_array($authorization));

        $bearerToken = current($authorization);
        $this->assertTrue(is_string($bearerToken));
        $this->assertEquals(0, strpos($bearerToken, 'Bearer '));
        $token = str_replace('Bearer ', '', $bearerToken);

        $lastReceivedToken = $sa->getLastReceivedToken();
        $this->assertArrayHasKey('access_token', $lastReceivedToken);
        $this->assertEquals($token, $lastReceivedToken['access_token']);
    }

    public function testShouldBeTheSameAsOAuth2WithTheSameScope()
    {
        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sa = new ServiceAccountJwtAccessCredentials($testJson);
        $this->assertNull($sa->getCacheKey());
    }

    public function testReturnsClientEmail()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials($testJson);
        $this->assertEquals($testJson['client_email'], $sa->getClientName());
    }
    public function testGetProjectId()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials($testJson);
        $this->assertEquals($testJson['project_id'], $sa->getProjectId());
    }

    public function testGetQuotaProject()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        $sa = new ServiceAccountJwtAccessCredentials($keyFile);
        $this->assertEquals('test_quota_project', $sa->getQuotaProject());
    }

    public function testUpdateMetadataWithUniverseDomainAlwaysUsesJwtAccess()
    {
        $testJson = $this->createTestJson() + ['universe_domain' => 'abc.xyz'];
        // jwt access should always be used when the universe domain is set,
        // even if scopes are supplied but useJwtAccessWithScope is false
        $scope = ['scope1', 'scope2'];
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );

        $metadata = $sa->updateMetadata(
            ['foo' => 'bar'],
            'https://example.com/service'
        );

        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $metadata
        );

        $authorization = $metadata[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertTrue(is_array($authorization));

        $token = current($authorization);
        $this->assertTrue(is_string($token));
        $this->assertEquals(0, strpos($token, 'Bearer '));

        // Ensure token is a self-signed JWT
        $token = substr($token, strlen('Bearer '));
        $this->assertEquals(2, substr_count($token, '.'));
        list($header, $payload, $sig) = explode('.', $token);
        $json = json_decode(base64_decode($payload), true);
        $this->assertTrue(is_array($json));
        // Ensure scopes exist
        $this->assertArrayHasKey('scope', $json);
        $this->assertEquals($json['scope'], implode(' ', $scope));
    }
}
