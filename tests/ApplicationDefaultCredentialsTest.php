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

use Google\Auth\ApplicationDefaultCredentials;
use Google\Auth\GCECredentials;
use Google\Auth\ServiceAccountCredentials;
use GuzzleHttp\Client;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;
use GuzzleHttp\Subscriber\Mock;

class ADCGetTest extends \PHPUnit_Framework_TestCase
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
    putenv(ServiceAccountCredentials::ENV_VAR);  // removes it from
  }

  /**
   * @expectedException DomainException
   */
  public function testIsFailsEnvSpecifiesNonExistentFile()
  {
    $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
    putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
    ApplicationDefaultCredentials::getCredentials('a scope');
  }

  public function testLoadsOKIfEnvSpecifiedIsValid()
  {
    $keyFile = __DIR__ . '/fixtures' . '/private.json';
    putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
    $this->assertNotNull(
        ApplicationDefaultCredentials::getCredentials('a scope')
    );
  }

  public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
  {
    putenv('HOME=' . __DIR__ . '/fixtures');
    $this->assertNotNull(
        ApplicationDefaultCredentials::getCredentials('a scope')
    );
  }

  /**
   * @expectedException DomainException
   */
  public function testFailsIfNotOnGceAndNoDefaultFileFound()
  {
    putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
    $client = new Client();
    // simulate not being GCE by return 500
    $client->getEmitter()->attach(new Mock([new Response(500)]));
    ApplicationDefaultCredentials::getCredentials('a scope', $client);
  }

  public function testSuccedsIfNoDefaultFilesButIsOnGCE()
  {
    $client = new Client();
    // simulate the response from GCE.
    $wantedTokens = [
        'access_token' => '1/abdef1234567890',
        'expires_in' => '57',
        'token_type' => 'Bearer',
    ];
    $jsonTokens = json_encode($wantedTokens);
    $plugin = new Mock([
        new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
        new Response(200, [], Stream::factory($jsonTokens)),
    ]);
    $client->getEmitter()->attach($plugin);
    $this->assertNotNull(
        ApplicationDefaultCredentials::getCredentials('a scope', $client)
    );
  }
}

class ADCGetFetcherTest extends \PHPUnit_Framework_TestCase
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
    putenv(ServiceAccountCredentials::ENV_VAR);  // removes it if assigned
  }

  /**
   * @expectedException DomainException
   */
  public function testIsFailsEnvSpecifiesNonExistentFile()
  {
    $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
    putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
    ApplicationDefaultCredentials::getFetcher('a scope');
  }

  public function testLoadsOKIfEnvSpecifiedIsValid()
  {
    $keyFile = __DIR__ . '/fixtures' . '/private.json';
    putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
    $this->assertNotNull(ApplicationDefaultCredentials::getFetcher('a scope'));
  }

  public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
  {
    putenv('HOME=' . __DIR__ . '/fixtures');
    $this->assertNotNull(ApplicationDefaultCredentials::getFetcher('a scope'));
  }

  /**
   * @expectedException DomainException
   */
  public function testFailsIfNotOnGceAndNoDefaultFileFound()
  {
    putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
    $client = new Client();
    // simulate not being GCE by return 500
    $client->getEmitter()->attach(new Mock([new Response(500)]));
    ApplicationDefaultCredentials::getFetcher('a scope', $client);
  }

  public function testSuccedsIfNoDefaultFilesButIsOnGCE()
  {
    $client = new Client();
    // simulate the response from GCE.
    $wantedTokens = [
        'access_token' => '1/abdef1234567890',
        'expires_in' => '57',
        'token_type' => 'Bearer',
    ];
    $jsonTokens = json_encode($wantedTokens);
    $plugin = new Mock([
        new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
        new Response(200, [], Stream::factory($jsonTokens)),
    ]);
    $client->getEmitter()->attach($plugin);
    $this->assertNotNull(
        ApplicationDefaultCredentials::getFetcher('a scope', $client));
  }
}
