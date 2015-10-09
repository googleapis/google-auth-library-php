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

use Google\Auth\AppIdentityCredentials;
use GuzzleHttp\Client;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;
use GuzzleHttp\Subscriber\Mock;

// included from tests\mocks\AppIdentityService.php
use google\appengine\api\app_identity\AppIdentityService;

class AppIdentityCredentialsOnAppEngineTest extends \PHPUnit_Framework_TestCase
{
  public function testIsFalseByDefault()
  {
    $this->assertFalse(AppIdentityCredentials::onAppEngine());
  }

  public function testIsTrueWhenServerSoftwareIsGoogleAppEngine()
  {
    $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
    $this->assertTrue(AppIdentityCredentials::onAppEngine());
  }
}

class AppIdentityCredentialsGetCacheKeyTest extends \PHPUnit_Framework_TestCase
{
  public function testShouldNotBeEmpty()
  {
    $g = new AppIdentityCredentials();
    $this->assertNotEmpty($g->getCacheKey());
  }
}

class AppIdentityCredentialsFetchAuthTokenTest extends \PHPUnit_Framework_TestCase
{
  public function testShouldBeEmptyIfNotOnAppEngine()
  {
    $g = new AppIdentityCredentials();
    $this->assertEquals(array(), $g->fetchAuthToken());
  }

  /* @expectedException */
  public function testTHrowsExceptionIfClassDoesntExist()
  {
    $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
    $g = new AppIdentityCredentials();
  }

  public function testReturnsExpectedToken()
  {
    // include the mock AppIdentityService class
    require_once __DIR__ . '/mocks/AppIdentityService.php';

    $wantedToken = [
        'access_token' => '1/abdef1234567890',
        'expires_in' => '57',
        'token_type' => 'Bearer',
    ];

    AppIdentityService::$accessToken = $wantedToken;

    // AppIdentityService::$accessToken = $wantedToken;
    $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';

    $g = new AppIdentityCredentials();
    $this->assertEquals($wantedToken, $g->fetchAuthToken());
  }
}
