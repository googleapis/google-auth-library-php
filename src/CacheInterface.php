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

/**
 * An interface implemented by services that provide simple cache.
 */
interface CacheInterface
{

  /**
   * Retrieves the data for the given key, or false if the key is unknown or
   * expired.
   *
   * @param String $key The key who's data to retrieve
   * @param boolean|int $expiration Expiration time in seconds
   */
  public function get($key, $expiration = false);

  /**
   * Store the key => $value
   *
   * Implementations will serialize $value.
   *
   * @param string $key the cachke key
   * @param string $value data
   */
  public function set($key, $value);

  /**
   * Removes the key/data pair.
   *
   * @param String $key
   */
  public function delete($key);
}
