<?php
/*
 * Copyright 2020 Google LLC
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

declare(strict_types=1);

namespace Google\Http\Client;

use Google\Http\PromiseInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class Psr18Client implements ClientInterface
{
    /**
     * @var \Psr\Http\Client\ClientInterface
     */
    private $client;

    /**
     * @param \Psr\Http\Client\ClientInterface $client
     */
    public function __construct(ClientInterface $client)
    {
        $this->client = $client;
    }

    /**
     * Accepts a PSR-7 request and an array of options and returns a PSR-7 response.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param array                              $options
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function send(
        RequestInterface $request,
        array $options = []
    ): ResponseInterface {
        if (!empty($options)) {
            // Ignore per-request options
        }

        return $this->client->sendRequest($request);
    }

    /**
     * Not implemented for PSR-18 clients.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @throws \RuntimeException
     */
    public function sendAsync(
        RequestInterface $request,
        array $options = []
    ): PromiseInterface {
        throw new \RuntimeException('async not supported for PSR-18 clients');
    }
}
