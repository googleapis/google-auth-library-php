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

namespace Google\Auth\Tests\Credentials;

use DomainException;
use Google\Auth\ApplicationDefaultCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\CredentialsLoader;
use Google\Auth\OAuth2;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;

class ServiceAccountCredentialsTest extends TestCase
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

    public function testShouldBeTheSameAsOAuth2WithTheSameScope()
    {
        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $o = new OAuth2(['scope' => $scope]);
        $this->assertSame(
            $testJson['client_email'] . ':' . $o->getCacheKey(),
            $sa->getCacheKey()
        );
    }

    public function testShouldBeTheSameAsOAuth2WithTheSameScopeWithSub()
    {
        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sub = 'sub123';
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson,
            $sub
        );
        $o = new OAuth2(['scope' => $scope]);
        $this->assertSame(
            $testJson['client_email'] . ':' . $o->getCacheKey() . ':' . $sub,
            $sa->getCacheKey()
        );
    }

    public function testShouldBeTheSameAsOAuth2WithTheSameScopeWithSubAddedLater()
    {
        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sub = 'sub123';
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson,
            null
        );
        $sa->setSub($sub);

        $o = new OAuth2(['scope' => $scope]);
        $this->assertSame(
            $testJson['client_email'] . ':' . $o->getCacheKey() . ':' . $sub,
            $sa->getCacheKey()
        );
    }

    public function testShouldFailIfScopeIsNotAValidType()
    {
        $this->expectexception(InvalidArgumentException::class);

        $testJson = $this->createTestJson();
        $notAnArrayOrString = new \stdClass();
        $sa = new ServiceAccountCredentials(
            $notAnArrayOrString,
            $testJson
        );
    }

    public function testShouldFailIfJsonDoesNotHaveClientEmail()
    {
        $this->expectException(InvalidArgumentException::class);

        $testJson = $this->createTestJson();
        unset($testJson['client_email']);
        $scope = ['scope/1', 'scope/2'];
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
    }

    public function testShouldFailIfJsonDoesNotHavePrivateKey()
    {
        $this->expectException(InvalidArgumentException::class);

        $testJson = $this->createTestJson();
        unset($testJson['private_key']);
        $scope = ['scope/1', 'scope/2'];
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
    }

    public function testFailsToInitalizeFromANonExistentFile()
    {
        $this->expectException(InvalidArgumentException::class);

        $keyFile = __DIR__ . '/../fixtures' . '/does-not-exist-private.json';
        new ServiceAccountCredentials('scope/1', $keyFile);
    }

    public function testInitalizeFromAFile()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        $this->assertNotNull(
            new ServiceAccountCredentials('scope/1', $keyFile)
        );
    }

    public function testFailsToInitializeFromInvalidJsonData()
    {
        $this->expectException(LogicException::class);

        $tmp = tmpfile();
        fwrite($tmp, '{');

        $path = stream_get_meta_data($tmp)['uri'];

        try {
            new ServiceAccountCredentials('scope/1', $path);
        } catch (\Exception $e) {
            fclose($tmp);
            throw $e;
        }
    }

    public function testIsNullIfEnvVarIsNotSet()
    {
        $this->assertNull(ServiceAccountCredentials::fromEnv());
    }

    /** @runInSeparateProcess */
    public function testFailsIfEnvSpecifiesNonExistentFile()
    {
        $this->expectException(DomainException::class);
        $keyFile = __DIR__ . '/../fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        ApplicationDefaultCredentials::getCredentials('a scope');
    }

    /** @runInSeparateProcess */
    public function testSucceedIfFileExists()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $this->assertNotNull(ApplicationDefaultCredentials::getCredentials('a scope'));
    }

    /** @runInSeparateProcess */
    public function testIsNullIfFileDoesNotExist()
    {
        putenv('HOME=' . __DIR__ . '/../not_exists_fixtures');
        $this->assertNull(
            ServiceAccountCredentials::fromWellKnownFile()
        );
    }

    /** @runInSeparateProcess */
    public function testSucceedIfFileIsPresent()
    {
        putenv('HOME=' . __DIR__ . '/../fixtures');
        $this->assertNotNull(
            ApplicationDefaultCredentials::getCredentials('a scope')
        );
    }

    public function testFailsOnClientErrors()
    {
        $this->expectException(\GuzzleHttp\Exception\ClientException::class);

        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $httpHandler = getHandler([
            new Response(400),
        ]);
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $sa->fetchAuthToken($httpHandler);
    }

    public function testFailsOnServerErrors()
    {
        $this->expectException(\GuzzleHttp\Exception\ServerException::class);

        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $httpHandler = getHandler([
            new Response(500),
        ]);
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $sa->fetchAuthToken($httpHandler);
    }

    public function testCanFetchCredsOK()
    {
        $testJson = $this->createTestJson();
        $testJsonText = json_encode($testJson);
        $scope = ['scope/1', 'scope/2'];
        $httpHandler = getHandler([
            new Response(200, [], Utils::streamFor($testJsonText)),
        ]);
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $tokens = $sa->fetchAuthToken($httpHandler);
        $this->assertEquals($testJson, $tokens);
    }

    public function testUpdateMetadataFunc()
    {
        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $access_token = 'accessToken123';
        $responseText = json_encode(['access_token' => $access_token]);
        $httpHandler = getHandler([
            new Response(200, [], Utils::streamFor($responseText)),
        ]);
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $update_metadata = $sa->getUpdateMetadataFunc();
        $this->assertTrue(is_callable($update_metadata));

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = ['foo' => 'bar'],
            $authUri = null,
            $httpHandler
        );
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );
        $this->assertEquals(
            $actual_metadata[CredentialsLoader::AUTH_METADATA_KEY],
            ['Bearer ' . $access_token]
        );
    }

    public function testShouldBeIdTokenWhenTargetAudienceIsSet()
    {
        $testJson = $this->createTestJson();
        $expectedToken = ['id_token' => 'idtoken12345'];
        $timesCalled = 0;
        $httpHandler = function ($request) use (&$timesCalled, $expectedToken) {
            $timesCalled++;
            parse_str($request->getBody(), $post);
            $this->assertArrayHasKey('assertion', $post);
            list($header, $payload, $sig) = explode('.', $post['assertion']);
            $jwtParams = json_decode(base64_decode($payload), true);
            $this->assertArrayHasKey('target_audience', $jwtParams);
            $this->assertEquals('a target audience', $jwtParams['target_audience']);

            return new Psr7\Response(200, [], Utils::streamFor(json_encode($expectedToken)));
        };
        $sa = new ServiceAccountCredentials(null, $testJson, null, 'a target audience');
        $this->assertEquals($expectedToken, $sa->fetchAuthToken($httpHandler));
        $this->assertEquals(1, $timesCalled);
    }

    public function testShouldBeOAuthRequestWhenSubIsSet()
    {
        $testJson = $this->createTestJson();
        $sub = 'sub12345';
        $timesCalled = 0;
        $httpHandler = function ($request) use (&$timesCalled, $sub) {
            $timesCalled++;
            parse_str($request->getBody(), $post);
            $this->assertArrayHasKey('assertion', $post);
            list($header, $payload, $sig) = explode('.', $post['assertion']);
            $jwtParams = json_decode(base64_decode($payload), true);
            $this->assertArrayHasKey('sub', $jwtParams);
            $this->assertEquals($sub, $jwtParams['sub']);

            return new Psr7\Response(200, [], Utils::streamFor(json_encode([
                'access_token' => 'token123'
            ])));
        };
        $sa = new ServiceAccountCredentials(null, $testJson, $sub);
        $this->assertEquals('token123', $sa->fetchAuthToken($httpHandler)['access_token']);
        $this->assertEquals(1, $timesCalled);
    }

    public function testSettingBothScopeAndTargetAudienceThrowsException()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Scope and targetAudience cannot both be supplied');

        $testJson = $this->createTestJson();
        $sa = new ServiceAccountCredentials(
            'a-scope',
            $testJson,
            null,
            'a-target-audience'
        );
    }

    public function testDomainWideDelegationOutsideGduThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'Service Account subject is configured for the credential. Domain-wide ' .
            'delegation is not supported in universes other than googleapis.com'
        );
        $testJson = $this->createTestJson() + ['universe_domain' => 'abc.xyz'];
        $sub = 'sub123';
        $sa = new ServiceAccountCredentials(
            null,
            $testJson,
            $sub
        );

        $sa->fetchAuthToken();
    }

    public function testReturnsClientEmail()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountCredentials('scope/1', $testJson);
        $this->assertEquals($testJson['client_email'], $sa->getClientName());
    }

    public function testGetProjectId()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountCredentials('scope/1', $testJson);
        $this->assertEquals($testJson['project_id'], $sa->getProjectId());
    }

    public function testGetQuotaProject()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        $sa = new ServiceAccountCredentials('scope/1', $keyFile);
        $this->assertEquals('test_quota_project', $sa->getQuotaProject());
    }
}
