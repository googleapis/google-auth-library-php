<?php
/*
 * Copyright 2021 Google Inc.
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

namespace Google\Auth\Middleware;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * RetryMiddleware is a Guzzle Middleware that allows for retrying certain error
 * codes automatically.
 *
 * Requests are accessed using the Simple API access developer key.
 */
class RetryMiddleware
{
    private $retryAttempts;

    /**
     * Creates a new RetryMiddleware.
     *
     * @param array $config {
     *     Configuration array
     *
     *     @type int $retryAttempts number of retry attempts.
     * }
     */
    public function __construct(array $config = [])
    {
        if (!isset($config['retryAttempts'])) {
            throw new \InvalidArgumentException('requires retryAttempts to be set');
        }

        $this->retryAttempts = $config['retryAttempts'];
    }

    /**
     * Retry the response if it has retryable error codes.
     *
     *   use Google\Auth\Middleware\AuthTokenMiddleware;
     *   use Google\Auth\Middleware\RetryMiddleware;
     *   use Google\Auth\OAuth2;
     *   use GuzzleHttp\Client;
     *   use GuzzleHttp\HandlerStack;
     *
     *   $config = [..<oauth config param>.];
     *   $oauth2 = new OAuth2($config)
     *   $authMiddleware = new AuthTokenMiddleware($oauth2);
     *   $retryMiddleware = new RetryMiddleware(['retryAttempts' => 3]);
     *   $stack = HandlerStack::create();
     *   $stack->push($authMiddleware);
     *   $stack->push($retryMiddleware);
     *
     *   $client = new Client([
     *       'handler' => $stack,
     *       'base_uri' => 'https://www.googleapis.com/taskqueue/v1beta2/projects/',
     *       'auth' => 'google_auth' // authorize all requests
     *   ]);
     *
     *   $res = $client->get('myproject/taskqueues/myqueue');
     *
     * @param callable $handler
     * @return \Closure
     */
    public function __invoke(callable $handler)
    {
        return function (RequestInterface $request, array $options) use ($handler) {
            $response = $handler($request, $options);
            for ($attempts = 0; $attempts < $this->retryAttempts; $attempts++) {
                if ($this->isRetryable($response)) {
                    $response = $handler($request, $options);
                }
            }
            return $response;
        };
    }

    private function isRetryable(ResponseInterface $response)
    {
        // no-op for now, this is a Proof of Concept!
        return false;
    }
}
