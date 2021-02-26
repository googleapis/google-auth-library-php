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

namespace Google\Auth\Http;

use Google\Http\ClientInterface;
use Google\Http\PromiseInterface;
use GuzzleHttp\Psr7;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class ApiKeyClient implements ClientInterface
{
    /**
     * @var string
     */
    private $apiKey;

    /**
     * @var \Google\Http\ClientInterface
     */
    private $httpClient;

    /**
     * @param string          $apiKey
     * @param ClientInterface $httpClient
     */
    public function __construct(
        string $apiKey,
        ClientInterface $httpClient = null
    ) {
        $this->apiKey = $apiKey;
        $this->httpClient = $httpClient ?: ClientFactory::build();
    }

    /**
     * Accepts a PSR-7 request and an array of options and returns a PSR-7
     * response.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param array                              $options [optional]
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function send(
        RequestInterface $request,
        array $options = []
    ): ResponseInterface {
        return $this->httpClient->send(
            $this->applyApiKey($request),
            $options
        );
    }

    /**
     * Accepts a PSR-7 request and an array of options and returns a
     * PromiseInterface.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param array                              $options [optional]
     *
     * @return \Google\Http\Promise\PromiseInterface
     */
    public function sendAsync(
        RequestInterface $request,
        array $options = []
    ): PromiseInterface {
        return $this->httpClient->sendAsync(
            $this->applyApiKey($request),
            $options
        );
    }

    private function applyApiKey(RequestInterface $request): RequestInterface
    {
        $query = Psr7\parse_query($request->getUri()->getQuery());
        $query['key'] = $this->apiKey;
        $uri = $request->getUri()->withQuery(Psr7\build_query($query));

        return $request->withUri($uri);
    }
}
