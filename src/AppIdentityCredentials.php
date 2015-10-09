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

namespace Google\Auth;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Client;

/**
 * The AppIdentityService class is automatically defined on App Engine,
 * so including this dependency is not necessary, and will result in a
 * PHP fatal error in the App Engine environment.
 */
use google\appengine\api\app_identity\AppIdentityService;

/**
 * AppIdentityCredentials supports authorization on Google App Engine.
 *
 * It can be used to authorize requests using the AuthTokenFetcher, but will
 * only succeed if being run on App Engine:
 *
 *   use GuzzleHttp\Client;
 *   use Google\Auth\AppIdentityCredentials;
 *   use Google\Auth\AuthTokenFetcher;
 *
 *   $gae = new AppIdentityCredentials('https://www.googleapis.com/auth/books');
 *   $subscriber = new AuthTokenFetcher($gae);
 *   $client = new Client([
 *      'base_url' => 'https://www.googleapis.com/books/v1',
 *      'defaults' => ['auth' => 'google_auth']
 *   ]);
 *   $client->setDefaultOption('verify', '/etc/ca-certificates.crt');
 *   $client->getEmitter()->attach($subscriber);
 *   $res = $client->get('volumes?q=Henry+David+Thoreau&country=US');
 *
 * In Guzzle 5 and below, the App Engine certificates need to be set on the
 * guzzle client in order for SSL requests to succeed.
 *
 *   $client->setDefaultOption('verify', '/etc/ca-certificates.crt');
 */
class AppIdentityCredentials extends CredentialsLoader
{
  private $scope;

  public function __construct($scope = array())
  {
    $this->scope = $scope;
  }

  /**
   * Determines if this an App Engine instance, by accessing the SERVER_SOFTWARE
   * environment variable.
   *
   * @return true if this an App Engine Instance, false otherwise
   */
  public static function onAppEngine()
  {
    return (isset($_SERVER['SERVER_SOFTWARE']) &&
        strpos($_SERVER['SERVER_SOFTWARE'], 'Google App Engine') !== false);
  }

  /**
   * Implements FetchAuthTokenInterface#fetchAuthToken.
   *
   * Fetches the auth tokens using the AppIdentityService if available.
   * As the AppIdentityService uses protobufs to fetch the access token,
   * the GuzzleHttp\ClientInterface instance passed in will not be used.
   *
   * @param $client GuzzleHttp\ClientInterface optional client.
   * @return array the auth metadata:
   *  array(2) {
   *   ["access_token"]=>
   *   string(3) "xyz"
   *   ["expiration_time"]=>
   *   string(10) "1444339905"
   *  }
   */
  public function fetchAuthToken(ClientInterface $unusedClient = null)
  {
    if (!self::onAppEngine()) {
      return array();
    }

    if (!class_exists('google\appengine\api\app_identity\AppIdentityService')) {
      throw new \Exception(
        'This class must be run in App Engine, or you must include the AppIdentityService '
        . 'mock class defined in tests/mocks/AppIdentityService.php'
      );
    }

    $token = AppIdentityService::getAccessToken($this->scope);

    return $token;
  }

  /**
   * Implements FetchAuthTokenInterface#getCacheKey.
   *
   * @return 'GOOGLE_AUTH_PHP_APPIDENTITY'
   */
  public function getCacheKey()
  {
    return 'GOOGLE_AUTH_PHP_APPIDENTITY';
  }
}
