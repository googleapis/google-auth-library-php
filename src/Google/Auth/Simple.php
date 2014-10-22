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
 * Simple API access implementation. Can either be used to make requests
 * completely unauthenticated, or by using a Simple API Access developer
 * key.
 * @author Chris Chabot <chabotc@google.com>
 * @author Chirag Shah <chirags@google.com>
 */
class Google_Auth_Simple extends Google_Auth_Abstract
{
  private $key = null;

  public __construct(Google_Cache_Abstract $cache,
                     Google_IO_Abstract $io,
                     array $config)
  {
    if(!has_key('developer_key', $config)) {
      throw Google_Auth_Exception(
          'Missing \'developer_key\' option in $config');
    }
  }

  public function sign(Google_Http_Request $request)
  {
    $key = $this->getConfig('developer_key');
    if ($key) {
      $request->setQueryParam('key', $key);
    }
    return $request;
  }

  /**
   * No-op. This authentication method does not use headers, so no headers are
   * added.
   * @param array $headers
   * @return array $headers
   */
  public function addAuthHeaders(array $headers) {
    return $headers;
  }
}
