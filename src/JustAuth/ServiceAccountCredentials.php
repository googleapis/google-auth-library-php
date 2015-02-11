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
use GuzzleHttp\Stream\Stream;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ServerException;

/**
 * ServiceAccountCredentials supports authorization using a Google service
 * account.
 *
 * (cf https://developers.google.com/accounts/docs/OAuth2ServiceAccount)
 *
 * It's initialized using the json key file that's downloadable from developer
 * console, which should contain a private_key and client_email fields that it
 * uses.
 *
 * Use it with AuthTokenFetcher to authorize http requests:
 *
 *   use GuzzleHttp\Client;
 *   use Google\Auth\ServiceAccountCredentials;
 *   use Google\Auth\AuthTokenFetcher;
 *
 *   $stream = Stream::factory(get_file_contents(<my_key_file>));
 *   $sa = new ServiceAccountCredentials(
 *       'https://www.googleapis.com/auth/taskqueue',
 *        $stream);
 *   $client = new Client([
 *      'base_url' => 'https://www.googleapis.com/taskqueue/v1beta2/projects/',
 *      'defaults' => ['auth' => 'google_auth']  // authorize all requests
 *   ]);
 *   $client->getEmitter()->attach(new AuthTokenFetcher($sa));
 *
 *   $res = $client->('myproject/taskqueues/myqueue');
 */
class ServiceAccountCredentials implements FetchAuthTokenInterface
{
  const DEFAULT_EXPIRY_MINUTES = 60;
  const ENV_VAR = 'GOOGLE_APPLICATION_CREDENTIALS';
  const TOKEN_CREDENTIAL_URI = 'https://www.googleapis.com/oauth2/v3/token';
  const WELL_KNOWN_PATH = 'gcloud/application_default_credentials.json';

  private static function unableToReadEnv($cause)
  {
    $msg = 'Unable to read the credential file specified by ';
    $msg .= ' GOOGLE_APPLICATION_CREDENTIALS: ';
    $msg .= $cause;
    return $msg;
  }

  private static function isOnWindows()
  {
    return strtoupper(substr(php_uname('s'), 0, 3)) === 'WIN';
  }

  /**
   * Create a new ServiceAccountCredentials from the path specified in the environment.
   *
   * Creates a credentials instance from the path specified in the environment
   * variable GOOGLE_APPLICATION_CREDENTIALS. Return null if
   * GOOGLE_APPLICATION_CREDENTIALS is not specified.
   *
   * @param string|array scope the scope of the access request, expressed
   *   either as an Array or as a space-delimited String.
   *
   * @return a ServiceAccountCredentials instance | null
   */
  public static function fromEnv($scope = null)
  {
    $path = getenv(self::ENV_VAR);
    if (empty($path)) {
      return null;
    }
    if (!file_exists($path)) {
      $cause = "file " . $path . " does not exist";
      throw new \DomainException(self::unableToReadEnv($cause));
    }
    $keyStream = Stream::factory(file_get_contents($path));
    return new ServiceAccountCredentials($scope, $keyStream);
  }

  /**
   * Create a new ServiceAccountCredentials from a well known path.
   *
   * The well known path is OS dependent:
   * - windows: %APPDATA%/gcloud/application_default_credentials.json
   * - others: $HOME/.config/gcloud/application_default_credentials.json
   *
   * If the file does not exists, this returns null.
   *
   * @param string|array scope the scope of the access request, expressed
   *   either as an Array or as a space-delimited String.
   *
   * @return a ServiceAccountCredentials instance | null
   */
  public static function fromWellKnownFile($scope = null)
  {
    $rootEnv = self::isOnWindows() ? 'APPDATA' : 'HOME';
    $root = getenv($rootEnv);
    $path = join(DIRECTORY_SEPARATOR, [$root, self::WELL_KNOWN_PATH]);
    if (!file_exists($path)) {
      return null;
    }
    $keyStream = Stream::factory(file_get_contents($path));
    return new ServiceAccountCredentials($scope, $keyStream);
  }

  /**
   * The OAuth2 instance used to conduct authorization.
   */
  private $auth;

  /**
   * Create a new ServiceAccountCredentials.
   *
   * @param string|array scope the scope of the access request, expressed
   *   either as an Array or as a space-delimited String.
   *
   * @param Stream jsonKeyStream read it to get the JSON credentials.
   *
   * @param string jsonKeyPath the path to a file containing JSON credentials.  If
   *   jsonKeyStream is set, it is ignored.
   *
   * @param string sub an email address account to impersonate, in situations when
   *   the service account has been delegated domain wide access.
   */
  public function __construct($scope, Stream $jsonKeyStream = null,
                              $jsonKeyPath = null, $sub = null)
  {
    if (is_null($jsonKeyStream)) {
      $jsonKeyStream = Stream::factory(file_get_contents($jsonKeyPath));
    }
    $jsonKey = json_decode($jsonKeyStream->getContents(), true);
    if (!array_key_exists('client_email', $jsonKey)) {
      throw new \InvalidArgumentException(
          'json key is missing the client_email field');
    }
    if (!array_key_exists('private_key', $jsonKey)) {
      throw new \InvalidArgumentException(
          'json key is missing the private_key field');
    }
    $this->auth = new OAuth2([
        'audience' => self::TOKEN_CREDENTIAL_URI,  // TODO: confirm this
        'issuer' => $jsonKey['client_email'],
        'scope' => $scope,
        'signingAlgorithm' => 'RS256',
        'signingKey' => $jsonKey['private_key'],
        'sub' => $sub,
        'tokenCredentialUri' => self::TOKEN_CREDENTIAL_URI
    ]);
  }

 /**
  * Implements FetchAuthTokenInterface#fetchAuthToken.
  */
  public function fetchAuthToken(ClientInterface $client = null)
  {
    return $this->auth->fetchAuthToken($client);
  }

 /**
  * Implements FetchAuthTokenInterface#getCacheKey.
  */
  public function getCacheKey()
  {
    return $this->auth->getCacheKey();
  }
}
