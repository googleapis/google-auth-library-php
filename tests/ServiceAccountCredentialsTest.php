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

namespace Google\Auth\Tests;

use Google\Auth\OAuth2;
use Google\Auth\ApplicationDefaultCredentials;
use Google\Auth\ServiceAccountCredentials;
use GuzzleHttp\Client;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;
use GuzzleHttp\Subscriber\Mock;

// Creates a standard JSON auth object for testing.
function createTestJson()
{
  return [
      'private_key_id' => 'key123',
      'private_key' => 'privatekey',
      'client_email' => 'test@example.com',
      'client_id' => 'client123',
      'type' => 'service_account'
  ];
}

class SACGetCacheKeyTest extends \PHPUnit_Framework_TestCase
{
  public function testShouldBeTheSameAsOAuth2WithTheSameScope()
  {
    $testJson = createTestJson();
    $scope = ['scope/1', 'scope/2'];
    $sa = new ServiceAccountCredentials(
        $scope,
        $testJson);
    $o = new OAuth2(['scope' => $scope]);
    $this->assertSame(
        $testJson['client_email'] . ':' . $o->getCacheKey(),
        $sa->getCacheKey()
    );
  }
}

class SACConstructorTest extends \PHPUnit_Framework_TestCase
{
  /**
   * @expectedException InvalidArgumentException
   */
  public function testShouldFailIfScopeIsNotAValidType()
  {
    $testJson = createTestJson();
    $notAnArrayOrString = new \stdClass();
    $sa = new ServiceAccountCredentials(
        $notAnArrayOrString,
        $testJson
    );
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testShouldFailIfJsonDoesNotHaveClientEmail()
  {
    $testJson = createTestJson();
    unset($testJson['client_email']);
    $scope = ['scope/1', 'scope/2'];
    $sa = new ServiceAccountCredentials(
        $scope,
        $testJson
    );
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testShouldFailIfJsonDoesNotHavePrivateKey()
  {
    $testJson = createTestJson();
    unset($testJson['private_key']);
    $scope = ['scope/1', 'scope/2'];
    $sa = new ServiceAccountCredentials(
        $scope,
        $testJson
    );
  }

  /**
   * @expectedException PHPUnit_Framework_Error_Warning
   */
  public function testFailsToInitalizeFromANonExistentFile()
  {
    $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
    new ServiceAccountCredentials('scope/1', null, $keyFile);
  }

  public function testInitalizeFromAFile()
  {
    $keyFile = __DIR__ . '/fixtures' . '/private.json';
    $this->assertNotNull(
        new ServiceAccountCredentials('scope/1', null, $keyFile)
    );
  }
}

class SACFromEnvTest extends \PHPUnit_Framework_TestCase
{
  protected function tearDown()
  {
    putenv(ServiceAccountCredentials::ENV_VAR);  // removes it from
  }

  public function testIsNullIfEnvVarIsNotSet()
  {
    $this->assertNull(ServiceAccountCredentials::fromEnv('a scope'));
  }

  /**
   * @expectedException DomainException
   */
  public function testFailsIfEnvSpecifiesNonExistentFile()
  {
    $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
    putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
    ApplicationDefaultCredentials::getCredentials('a scope');
  }

  public function testSucceedIfFileExists()
  {
    $keyFile = __DIR__ . '/fixtures' . '/private.json';
    putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
    $this->assertNotNull(ApplicationDefaultCredentials::getCredentials('a scope'));
  }
}

class SACFromWellKnownFileTest extends \PHPUnit_Framework_TestCase
{
  private $originalHome;

  protected function setUp()
  {
    $this->originalHome = getenv('HOME');
  }

  protected function tearDown()
  {
    if ($this->originalHome != getenv('HOME')) {
      putenv('HOME=' . $this->originalHome);
    }
  }

  public function testIsNullIfFileDoesNotExist()
  {
    $this->assertNull(
        ServiceAccountCredentials::fromWellKnownFile('a scope')
    );
  }

  public function testSucceedIfFileIsPresent()
  {
    putenv('HOME=' . __DIR__ . '/fixtures');
    $this->assertNotNull(
        ApplicationDefaultCredentials::getCredentials('a scope')
    );
  }
}

class SACFetchAuthTokenTest extends \PHPUnit_Framework_TestCase
{
  private $privateKey;

  public function setUp()
  {
    $this->privateKey =
        file_get_contents(__DIR__ . '/fixtures' . '/private.pem');
  }

  private function createTestJson()
  {
    $testJson = createTestJson();
    $testJson['private_key'] = $this->privateKey;
    return $testJson;
  }

  /**
   * @expectedException GuzzleHttp\Exception\ClientException
   */
  public function testFailsOnClientErrors()
  {
    $testJson = $this->createTestJson();
    $scope = ['scope/1', 'scope/2'];
    $client = new Client();
    $client->getEmitter()->attach(new Mock([new Response(400)]));
    $sa = new ServiceAccountCredentials(
        $scope,
        $testJson
    );
    $sa->fetchAuthToken($client);
  }

  /**
   * @expectedException GuzzleHttp\Exception\ServerException
   */
  public function testFailsOnServerErrors()
  {
    $testJson = $this->createTestJson();
    $scope = ['scope/1', 'scope/2'];
    $client = new Client();
    $client->getEmitter()->attach(new Mock([new Response(500)]));
    $sa = new ServiceAccountCredentials(
        $scope,
        $testJson
    );
    $sa->fetchAuthToken($client);
  }

  public function testCanFetchCredsOK()
  {
    $testJson = $this->createTestJson();
    $testJsonText = json_encode($testJson);
    $scope = ['scope/1', 'scope/2'];
    $client = new Client();
    $testResponse = new Response(200, [], Stream::factory($testJsonText));
    $client->getEmitter()->attach(new Mock([$testResponse]));
    $sa = new ServiceAccountCredentials(
        $scope,
        $testJson
    );
    $tokens = $sa->fetchAuthToken($client);
    $this->assertEquals($testJson, $tokens);
  }
}
