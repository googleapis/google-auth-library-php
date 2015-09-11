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
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ServerException;

/**
 * GCECredentials supports authorization on Google Compute Engine.
 *
 * It can be used to authorize requests using the AuthTokenFetcher, but will
 * only succeed if being run on GCE:
 *
 *   use GuzzleHttp\Client;
 *   use Google\Auth\GCECredentials;
 *   use Google\Auth\AuthTokenFetcher;
 *
 *   $gce = new GCECredentials();
 *   $scoped = new AuthTokenFetcher($gce);
 *   $client = new Client([
 *      'base_url' => 'https://www.googleapis.com/taskqueue/v1beta2/projects/',
 *      'defaults' => ['auth' => 'google_auth']
 *   ]);
 *   $client->getEmitter()->attach($gce);
 *   $res = $client->get('myproject/taskqueues/myqueue');
 */
class GCECredentials extends CredentialsLoader
{
  /**
   * The metadata IP address on appengine instances.
   *
   * The IP is used instead of the domain 'metadata' to avoid slow responses
   * when not on Compute Engine.
   */
  const METADATA_IP = '169.254.169.254';

  /**
   * The metadata path of the default token.
   */
  const TOKEN_URI_PATH = 'v1/instance/service-accounts/default/token';

  /**
   * The header whose presence indicates GCE presence.
   */
  const FLAVOR_HEADER = 'Metadata-Flavor';

  /**
   * Flag used to ensure that the onGCE test is only done once;
   */
  private $hasCheckedOnGce = false;

  /**
   * Flag that stores the value of the onGCE check.
   */
  private $isOnGce = false;

  /**
   * The full uri for accessing the default token.
   */
  public static function getTokenUri()
  {
    $base = 'http://' . self::METADATA_IP . '/computeMetadata/';
    return $base . self::TOKEN_URI_PATH;
  }

  /**
   * Determines if this a GCE instance, by accessing the expected metadata
   * host.
   * If $client is not specified a new GuzzleHttp\Client instance is used.
   *
   * @param $client GuzzleHttp\ClientInterface optional client.
   * @return true if this a GCEInstance false otherwise
   */
  public static function onGce(ClientInterface $client = null)
  {
    if (is_null($client)) {
      $client = new Client();
    }
    $checkUri = 'http://' . self::METADATA_IP;
    try {
      // Comment from: oauth2client/client.py
      //
      // Note: the explicit `timeout` below is a workaround. The underlying
      // issue is that resolving an unknown host on some networks will take
      // 20-30 seconds; making this timeout short fixes the issue, but
      // could lead to false negatives in the event that we are on GCE, but
      // the metadata resolution was particularly slow. The latter case is
      // "unlikely".
      $resp = $client->get($checkUri, ['timeout' => 0.3]);
      return $resp->getHeader(self::FLAVOR_HEADER) == 'Google';
    } catch (ClientException $e) {
      return false;
    } catch (ServerException $e) {
      return false;
    } catch (RequestException $e) {
      return false;
    }
  }

  /**
   * Implements FetchAuthTokenInterface#fetchAuthToken.
   *
   * Fetches the auth tokens from the GCE metadata host if it is available.
   * If $client is not specified a new GuzzleHttp\Client instance is used.
   *
   * @param $client GuzzleHttp\ClientInterface optional client.
   * @return array the response
   */
  public function fetchAuthToken(ClientInterface $client = null)
  {
    if (is_null($client)) {
      $client = new Client();
    }
    if (!$this->hasCheckedOnGce) {
      $this->isOnGce = self::onGce($client);
    }
    if (!$this->isOnGce) {
      return array();  // return an empty array with no access token
    }
    $resp = $client->get(self::getTokenUri(),
                         [ 'headers' => [self::FLAVOR_HEADER => 'Google']]);
    return $resp->json();
  }

  /**
   * Implements FetchAuthTokenInterface#getCacheKey.
   *
   * @return 'GOOGLE_AUTH_PHP_GCE'
   */
  public function getCacheKey() {
    return 'GOOGLE_AUTH_PHP_GCE';
  }
}
