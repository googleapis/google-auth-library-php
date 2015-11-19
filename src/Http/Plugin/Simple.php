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

namespace Google\Auth\Http\Plugin;

use Http\Client\Plugin\Plugin;
use Psr\Http\Message\RequestInterface;

/**
 * Simple is a Guzzle Subscriber that implements Google's Simple API access.
 *
 * Requests are accessed using the Simple API access developer key.
 */
class Simple implements Plugin
{
    /** @var array configuration */
  private $config;

  /**
   * Create a new Simple plugin.
   *
   * The configuration array expects one option
   * - key: required, otherwise InvalidArgumentException is thrown
   *
   * @param array $config Configuration array
   */
  public function __construct(array $config)
  {
      if (!isset($config['key'])) {
          throw new \InvalidArgumentException('"key" is a required config value');
      }
      $this->config = $config;
  }

    public function handleRequest(RequestInterface $request, callable $next, callable $first)
    {
        $newRequest = $request->getUri()->withQuery(http_build_query($this->config));

        return $next($newRequest);
    }
}
