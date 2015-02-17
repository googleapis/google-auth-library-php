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

use Google\Auth\GCECredentials;
use GuzzleHttp\Client;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;
use GuzzleHttp\Subscriber\Mock;

class GCECredentialsOnGCETest extends \PHPUnit_Framework_TestCase
{
  public function testIsFalseOnClientErrorStatus()
  {
    $client = new Client();
    $client->getEmitter()->attach(new Mock([new Response(400)]));
    $this->assertFalse(GCECredentials::onGCE($client));
  }

  public function testIsFalseOnServerErrorStatus()
  {
    $client = new Client();
    $client->getEmitter()->attach(new Mock([new Response(500)]));
    $this->assertFalse(GCECredentials::onGCE($client));
  }

  public function testIsFalseOnOkStatusWithoutExpectedHeader()
  {
    $client = new Client();
    $client->getEmitter()->attach(new Mock([new Response(200)]));
    $this->assertFalse(GCECredentials::onGCE($client));
  }

  public function testIsOkIfGoogleIsTheFlavor()
  {
    $client = new Client();
    $plugin = new Mock([new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google'])]);
    $client->getEmitter()->attach($plugin);
    $this->assertTrue(GCECredentials::onGCE($client));
  }
}

class GCECredentialsGetCacheKeyTest extends \PHPUnit_Framework_TestCase
{
  public function testShouldNotBeEmpty()
  {
    $g = new GCECredentials();
    $this->assertNotEmpty($g->getCacheKey());
  }
}

class GCECredentialsFetchAuthTokenTest extends \PHPUnit_Framework_TestCase
{
  public function testShouldBeEmptyIfNotOnGCE()
  {
    $client = new Client();
    $client->getEmitter()->attach(new Mock([new Response(500)]));
    $g = new GCECredentials();
    $this->assertEquals(array(), $g->fetchAuthToken($client));
  }

  /**
   * @expectedException GuzzleHttp\Exception\ParseException
   */
  public function testShouldFailIfResponseIsNotJson()
  {
    $notJson = '{"foo": , this is cannot be passed as json" "bar"}';
    $client = new Client();
    $plugin = new Mock([
        new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
        new Response(200, [], Stream::factory($notJson)),
    ]);
    $client->getEmitter()->attach($plugin);
    $g = new GCECredentials();
    $this->assertEquals(array(), $g->fetchAuthToken($client));
  }

  public function testShouldReturnTokenInfo()
  {
    $wantedTokens = [
        'access_token' => '1/abdef1234567890',
        'expires_in' => '57',
        'token_type' => 'Bearer',
    ];
    $jsonTokens = json_encode($wantedTokens);
    $client = new Client();
    $plugin = new Mock([
        new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
        new Response(200, [], Stream::factory($jsonTokens)),
    ]);
    $client->getEmitter()->attach($plugin);
    $g = new GCECredentials();
    $this->assertEquals($wantedTokens, $g->fetchAuthToken($client));
  }
}
