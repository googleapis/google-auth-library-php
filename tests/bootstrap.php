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

error_reporting(E_ALL | E_STRICT);

require dirname(__DIR__) . '/vendor/autoload.php';
date_default_timezone_set('UTC');

use Google\Http\ClientInterface;
use Google\Http\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

function httpClientWithResponses(array $mockResponses = [])
{
    $mock = new \GuzzleHttp\Handler\MockHandler($mockResponses);

    $handler = \GuzzleHttp\HandlerStack::create($mock);
    $client = new \GuzzleHttp\Client(['handler' => $handler]);

    return new \Google\Http\Client\GuzzleClient($client);
}

function httpClientFromCallable(callable $httpHandler): ClientInterface
{
    return new class($httpHandler) implements ClientInterface {
        private $httpHandler;

        public function __construct(callable $httpHandler)
        {
            $this->httpHandler = $httpHandler;
        }

        public function send(
            RequestInterface $request,
            array $options = []
        ): ResponseInterface {
            $httpHandler = $this->httpHandler;

            return $httpHandler($request);
        }

        public function sendAsync(
            RequestInterface $request,
            array $options = []
        ): PromiseInterface {
            // no op
        }
    };
}
