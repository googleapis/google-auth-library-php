<?php
/*
 * Copyright 2014 Google Inc.
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

require_once realpath(dirname(__FILE__) . '/../autoload.php');

class CurlTest extends PHPUnit_Framework_TestCase
{
  // Requires cURL to be compiled in to PHP
  public function testSimpleRequest()
  {
    $request = new Google_Http_Request('http://www.google.com');
    $curl = new Google_IO_Curl(0, new Google_Cache_Null());
    list($response_data,
         $response_headers,
         $response_http_code) = $curl->executeRequest($request);
    $this->assertEquals(200, $response_http_code);
  }
}

?>
