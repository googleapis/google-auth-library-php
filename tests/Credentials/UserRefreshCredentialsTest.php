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
use Google\Auth\Credentials\UserRefreshCredentials;
use Google\Auth\OAuth2;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;

class UserRefreshCredentialsTest extends TestCase
{
    private $originalHome;

    protected function setUp(): void
    {
        $this->originalHome = getenv('HOME');
    }

    protected function tearDown(): void
    {
        putenv(UserRefreshCredentials::ENV_VAR);  // removes it from
        if ($this->originalHome != getenv('HOME')) {
            putenv('HOME=' . $this->originalHome);
        }
    }

    // Creates a standard JSON auth object for testing.
    private function createTestJson()
    {
        return [
            'client_id' => 'client123',
            'client_secret' => 'clientSecret123',
            'refresh_token' => 'refreshToken123',
            'type' => 'authorized_user',
        ];
    }

    public function testShouldBeTheSameAsOAuth2WithTheSameScope()
    {
        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sa = new UserRefreshCredentials(
            $scope,
            $testJson
        );
        $o = new OAuth2(['scope' => $scope]);
        $this->assertSame(
            $testJson['client_id'] . '.' . implode(' ', $scope),
            $sa->getCacheKey()
        );
    }

    public function testShouldFailIfScopeIsNotAValidType()
    {
        $this->expectException(InvalidArgumentException::class);
        $testJson = $this->createTestJson();
        $notAnArrayOrString = new \stdClass();
        $sa = new UserRefreshCredentials(
            $notAnArrayOrString,
            $testJson
        );
    }

    public function testShouldFailIfJsonDoesNotHaveClientSecret()
    {
        $this->expectException(InvalidArgumentException::class);
        $testJson = $this->createTestJson();
        unset($testJson['client_secret']);
        $scope = ['scope/1', 'scope/2'];
        $sa = new UserRefreshCredentials(
            $scope,
            $testJson
        );
    }

    public function testShouldFailIfJsonDoesNotHaveRefreshToken()
    {
        $this->expectException(InvalidArgumentException::class);
        $testJson = $this->createTestJson();
        unset($testJson['refresh_token']);
        $scope = ['scope/1', 'scope/2'];
        $sa = new UserRefreshCredentials(
            $scope,
            $testJson
        );
    }

    public function testShouldFailIfJsonDoesNotHaveClientId()
    {
        $this->expectException(InvalidArgumentException::class);
        $testJson = $this->createTestJson();
        unset($testJson['client_id']);
        $scope = ['scope/1', 'scope/2'];
        $sa = new UserRefreshCredentials(
            $scope,
            $testJson
        );
    }

    public function testFailsToInitalizeFromANonExistentFile()
    {
        $this->expectException(InvalidArgumentException::class);
        $keyFile = __DIR__ . '/../fixtures/does-not-exist-private.json';
        new UserRefreshCredentials('scope/1', $keyFile);
    }

    public function testInitalizeFromAFile()
    {
        $keyFile = __DIR__ . '/../fixtures2' . '/private.json';
        $this->assertNotNull(
            new UserRefreshCredentials('scope/1', $keyFile)
        );
    }

    public function testFailsToInitializeFromInvalidJsonData()
    {
        $this->expectException(LogicException::class);

        $tmp = tmpfile();
        fwrite($tmp, '{');

        $path = stream_get_meta_data($tmp)['uri'];

        try {
            new UserRefreshCredentials('scope/1', $path);
        } catch (\Exception $e) {
            fclose($tmp);
            throw $e;
        }
    }

    public function testValid3LOauthCreds()
    {
        $keyFile = __DIR__ . '/../fixtures2/valid_oauth_creds.json';
        $this->assertNotNull(
            new UserRefreshCredentials('scope/1', $keyFile)
        );
    }

    public function testIsNullIfEnvVarIsNotSet()
    {
        $this->assertNull(UserRefreshCredentials::fromEnv('a scope'));
    }

    public function testFailsIfEnvSpecifiesNonExistentFile()
    {
        $this->expectException(DomainException::class);
        $keyFile = __DIR__ . '/../fixtures/does-not-exist-private.json';
        putenv(UserRefreshCredentials::ENV_VAR . '=' . $keyFile);
        UserRefreshCredentials::fromEnv('a scope');
    }

    public function testSucceedIfFileExists()
    {
        $keyFile = __DIR__ . '/../fixtures2/private.json';
        putenv(UserRefreshCredentials::ENV_VAR . '=' . $keyFile);
        $this->assertNotNull(ApplicationDefaultCredentials::getCredentials('a scope'));
    }

    public function testIsNullIfFileDoesNotExist()
    {
        putenv('HOME=' . __DIR__ . '/../not_exist_fixtures');
        $this->assertNull(
            UserRefreshCredentials::fromWellKnownFile('a scope')
        );
    }

    public function testSucceedIfFileIsPresent()
    {
        putenv('HOME=' . __DIR__ . '/../fixtures2');
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
        $sa = new UserRefreshCredentials(
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
        $sa = new UserRefreshCredentials(
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
        $sa = new UserRefreshCredentials(
            $scope,
            $testJson
        );
        $tokens = $sa->fetchAuthToken($httpHandler);
        $this->assertEquals($testJson, $tokens);
    }

    public function testGetGrantedScope()
    {
        $responseJson = json_encode(['scope' => 'scope/1 scope/2']);
        $httpHandler = getHandler([
            new Response(200, [], Utils::streamFor($responseJson)),
        ]);
        $sa = new UserRefreshCredentials(
            '',
            $this->createTestJson()
        );
        $sa->fetchAuthToken($httpHandler);
        $this->assertEquals('scope/1 scope/2', $sa->getGrantedScope());
    }

    public function testShouldBeIdTokenWhenTargetAudienceIsSet()
    {
        $testJson = $this->createTestJson();
        $expectedToken = ['id_token' => 'idtoken12345'];
        $timesCalled = 0;
        $httpHandler = function ($request) use (&$timesCalled, $expectedToken) {
            $timesCalled++;
            parse_str($request->getBody(), $post);

            $this->assertArrayHasKey('target_audience', $post);
            $this->assertEquals('a target audience', $post['target_audience']);
            return new Response(200, [], Utils::streamFor(json_encode($expectedToken)));
        };
        $sa = new UserRefreshCredentials(null, $testJson, 'a target audience');
        $this->assertEquals($expectedToken, $sa->fetchAuthToken($httpHandler));
        $this->assertEquals(1, $timesCalled);
    }

    public function testSettingBothScopeAndTargetAudienceThrowsException()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Scope and targetAudience cannot both be supplied');

        $testJson = $this->createTestJson();
        $sa = new UserRefreshCredentials('a-scope', $testJson, 'a-target-audience');
    }

    public function testGetQuotaProject()
    {
        $keyFile = __DIR__ . '/../fixtures2' . '/private.json';
        $sa = new UserRefreshCredentials('a-scope', $keyFile);
        $this->assertEquals('test_quota_project', $sa->getQuotaProject());
    }
}
