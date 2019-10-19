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

namespace Google\Auth\Middleware;

use Google\Auth\FetchIdTokenInterface;
use Psr\Http\Message\RequestInterface;

/**
 * IdTokenMiddleware is a Guzzle Middleware that adds an Authorization header
 * provided by an object implementing FetchIdTokenInterface.
 *
 * The FetchIdTokenInterface#fetchIdToken is used to obtain an ID token
 * to be added to the authorization header.
 *
 * Requests will be accessed with the authorization header:
 *
 * 'authorization' 'Bearer <value of id_token>'
 */
class IdTokenMiddleware
{
    /**
     * @var callback
     */
    private $httpHandler;

    /**
     * @var FetchIdTokenInterface
     */
    private $fetcher;

    /**
     * Creates a new IdTokenMiddleware.
     *
     * @param FetchIdTokenInterface $fetcher is used to fetch the auth token
     * @param callable $httpHandler (optional) callback which delivers psr7 request
     */
    public function __construct(
        FetchIdTokenInterface $fetcher,
        callable $httpHandler = null
    ) {
        $this->fetcher = $fetcher;
        $this->httpHandler = $httpHandler;
    }

    /**
     * Updates the request with an Authorization header when auth is 'google_id_token'.
     *
     *   use Google\Auth\Middleware\IdTokenMiddleware;
     *   use Google\Auth\OAuth2;
     *   use GuzzleHttp\Client;
     *   use GuzzleHttp\HandlerStack;
     *
     *   $config = [..<oauth config param>.];
     *   $oauth2 = new OAuth2($config)
     *   $middleware = new IdTokenMiddleware($oauth2);
     *   $stack = HandlerStack::create();
     *   $stack->push($middleware);
     *
     *   $client = new Client([
     *       'handler' => $stack,
     *       'base_uri' => 'https://IAP_PROJECT_ID.appspot.com',
     *       'auth' => 'google_id_token' // authorize all requests
     *   ]);
     *
     *   $res = $client->get('/');
     *
     * @param callable $handler
     *
     * @return \Closure
     */
    public function __invoke(callable $handler)
    {
        return function (RequestInterface $request, array $options) use ($handler) {
            // Requests using "auth"="google_id_token" will be authorized.
            if (!isset($options['auth']) || $options['auth'] !== 'google_id_token') {
                return $handler($request, $options);
            }

            $idToken = $this->fetcher->fetchIdToken($this->httpHandler);
            $request = $request->withHeader('authorization', 'Bearer ' . $idToken);

            return $handler($request, $options);
        };
    }
}
