<?php
/*
 * Copyright 2010 Google Inc.
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

require_once realpath(dirname(__FILE__) . '/../../../autoload.php');

/**
 * Abstract class for the Authentication in the API client
 * @author Chris Chabot <chabotc@google.com>
 *
 */
abstract class Google_Auth_Abstract
{
  /**
   * @var Google_Cache_Abstract The cache
   */
  protected $cache;

  /**
   * @var Google_IO_Abstract The IO handler
   */
  protected $io;

  /**
   * @var array Configuration options for this specific class
   */
  private $config;

  public function __construct(Google_Cache_Abstract $cache,
                              Google_IO_Abstract $io,
                              array $config = array())
  {
    $this->cache = $cache;
    $this->io = $io;
    $this->config = $config;
  }

  protected function getConfig($name)
  {
    return $this->config[$name];
  }

  /**
   * An utility function that first calls $this->auth->sign($request) and then
   * executes makeRequest() on that signed request. Used for when a request
   * should be authenticated
   * @param Google_Http_Request $request
   * @return Google_Http_Request The resulting HTTP response including the
   * responseHttpCode, responseHeaders and responseBody.
   */
  public function authenticatedRequest(Google_Http_Request $request)
  {
    $request = $this->sign($request);
    return $this->io->makeRequest($request);
  }

  /**
   * Modify the request by adding the relevant auth headers
   * @param Google_Http_Request $request
   * @return Google_Http_Request $request
   */
  public function sign(Google_Http_Request $request) {
    $request->setRequestHeaders($this->addAuthHeaders(array()));
    return $request;
  }

  /**
   * Adds any headers required to authenticate with this method to the given
   * array of headers
   * @param array $headers The headers to add auth information to
   * @return array $headers
   */
  abstract public function addAuthHeaders(array $headers);
}
