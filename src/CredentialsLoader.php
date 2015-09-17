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
 * CredentialsLoader contains the behaviour used to locate and find default
 * credentials files on the file system.
 */
abstract class CredentialsLoader implements FetchAuthTokenInterface
{
  const TOKEN_CREDENTIAL_URI = 'https://www.googleapis.com/oauth2/v3/token';
  const ENV_VAR = 'GOOGLE_APPLICATION_CREDENTIALS';
  const WELL_KNOWN_PATH = 'gcloud/application_default_credentials.json';
  const NON_WINDOWS_WELL_KNOWN_PATH_BASE = '.config';
  const AUTH_METADATA_KEY = 'Authorization';

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
   * The OAuth2 instance used to conduct authorization.
   */
  protected $auth;

  /**
   * Create a credentials instance from the path specified in the environment.
   *
   * Creates a credentials instance from the path specified in the environment
   * variable GOOGLE_APPLICATION_CREDENTIALS. Return null if
   * GOOGLE_APPLICATION_CREDENTIALS is not specified.
   *
   * @param string|array scope the scope of the access request, expressed
   *   either as an Array or as a space-delimited String.
   *
   * @return a Credentials instance | null
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
    return static::makeCredentials($scope, $keyStream);
  }

  /**
   * Create a credentials instance from a well known path.
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
   * @return a Credentials instance | null
   */
  public static function fromWellKnownFile($scope = null)
  {
    $rootEnv = self::isOnWindows() ? 'APPDATA' : 'HOME';
    $path = [getenv($rootEnv)];
    if (!self::isOnWindows()) {
      $path[] = self::NON_WINDOWS_WELL_KNOWN_PATH_BASE;
    }
    $path[] = self::WELL_KNOWN_PATH;
    $path = join(DIRECTORY_SEPARATOR, $path);
    if (!file_exists($path)) {
      return null;
    }
    $keyStream = Stream::factory(file_get_contents($path));
    return static::makeCredentials($scope, $keyStream);
  }

  /**
   * Create a new Credentials instance.
   *
   * @param string|array scope the scope of the access request, expressed
   *   either as an Array or as a space-delimited String.
   *
   * @param Stream jsonKeyStream read it to get the JSON credentials.
   *
   */
  public static function makeCredentials($scope, Stream $jsonKeyStream)
  {
    $jsonKey = json_decode($jsonKeyStream->getContents(), true);
    if (!array_key_exists('type', $jsonKey)) {
      throw new \InvalidArgumentException(
          'json key is missing the type field');
    }

    if ($jsonKey['type'] == 'service_account') {
      return new ServiceAccountCredentials($scope, $jsonKey);

    } else if ($jsonKey['type'] == 'authorized_user') {
      return new UserRefreshCredentials($scope, $jsonKey);

    } else {
      throw new \InvalidArgumentException(
          'invalid value in the type field');
    }
  }

  /**
   * export a callback function which updates runtime metadata
   *
   * @return an updateMetadata function
   */
  public function getUpdateMetadataFunc()
  {
    return array($this, 'updateMetadata');
  }

  /**
   * Updates metadata with the authorization token
   *
   * @param $metadata array metadata hashmap
   * @param $authUri string optional auth uri
   * @param $client optional client interface
   *
   * @return array updated metadata hashmap
   */
  public function updateMetadata($metadata,
                                 $authUri = null,
                                 ClientInterface $client = null)
  {
    $result = $this->fetchAuthToken($client);
    if (!isset($result['access_token'])) {
      return $metadata;
    }
    $metadata_copy = $metadata;
    $metadata_copy[self::AUTH_METADATA_KEY] = array('Bearer ' . $result['access_token']);
    return $metadata_copy;
  }
}
