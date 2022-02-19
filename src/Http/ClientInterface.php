<?php
/**
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Google\Http;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

interface ClientInterface
{
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
    ): ResponseInterface;

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
    ): PromiseInterface;
}
