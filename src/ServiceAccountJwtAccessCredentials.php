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
 * Authenticates requests using Google's Service Account credentials via
 * JWT Access.
 *
 * This class allows authorizing requests for service accounts directly
 * from credentials from a json key file downloaded from the developer
 * console (via 'Generate new Json Key').  It is not part of any OAuth2
 * flow, rather it creates a JWT and sends that as a credential.
 */
class ServiceAccountJwtAccessCredentials extends CredentialsLoader
{
  /**
   * Create a new ServiceAccountJwtAccessCredentials.
   *
   * @param array jsonKey JSON credentials.
   */
  public function __construct($jsonKey)
  {
    if (!array_key_exists('client_email', $jsonKey)) {
      throw new \InvalidArgumentException(
          'json key is missing the client_email field');
    }
    if (!array_key_exists('private_key', $jsonKey)) {
      throw new \InvalidArgumentException(
          'json key is missing the private_key field');
    }
    $this->auth = new OAuth2([
      'issuer' => $jsonKey['client_email'],
      'sub' => $jsonKey['client_email'],
      'signingAlgorithm' => 'RS256',
      'signingKey' => $jsonKey['private_key'],
    ]);
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
    if (empty($authUri)) {
      return $metadata;
    }

    $this->auth->setAudience($authUri);
    return parent::updateMetadata($metadata, $authUri, $client);
  }

 /**
  * Implements FetchAuthTokenInterface#fetchAuthToken.
  */
  public function fetchAuthToken(ClientInterface $unusedClient = null)
  {
    $audience = $this->auth->getAudience();
    if (empty($audience)) {
      return null;
    }

    $access_token = $this->auth->toJwt();
    return array('access_token' => $access_token);
  }

  /**
   * Implements FetchAuthTokenInterface#getCacheKey.
   */
  public function getCacheKey()
  {
    return $this->auth->getCacheKey();
  }
}
