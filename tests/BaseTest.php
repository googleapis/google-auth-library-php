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

require_once 'bootstrap.php';

class BaseTest extends PHPUnit_Framework_TestCase {
  const KEY = "";
  private $token;
  private $cache;

  public function __construct()
  {
    parent::__construct();
    // Fill in a token JSON here and you can test the oauth token
    // requiring functions.
    // $this->token = '';
    $this->cache = new Google_Cache_Null();
  }

  public function getCache() {
    return $this->cache;
  }

  public function checkToken()
  {
    if (!strlen($this->token)) {
      $this->markTestSkipped('Test requires access token');
      return false;
    }
    return true;
  }

  /**
   * This is just here to stop the warning about no tests in this class
   */
  public function testDummy() {
    $this->assertTrue(true);
  }
}
