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

namespace Google\Auth\Http\Tests;

use Google\Auth\Http\ApiKeyClient;
use Google\Http\ClientInterface;
use Google\Http\PromiseInterface;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Http\Message\RequestInterface;

/**
 * @internal
 * @covers \Google\Auth\Http\ApiKeyClient
 */
class ApiKeyClientTest extends TestCase
{
    public function testSend()
    {
        $apiKey = 'apikey123';
        $phpunit = $this;
        $client = $this->prophesize(ClientInterface::class);
        $client->send(Argument::type(RequestInterface::class), [])
            ->shouldBeCalledTimes(1)
            ->will(function (array $args) use ($phpunit) {
                $request = $args[0];
                $uri = $request->getUri();
                $phpunit->assertEquals('key=apikey123', $uri->getQuery());

                return new Response(200);
            })
        ;

        $apiKeyClient = new ApiKeyClient($apiKey, $client->reveal());
        $apiKeyClient->send(new Request('GET', 'http://foo/'));
    }

    public function testSendAsync()
    {
        $apiKey = 'apikey123';
        $phpunit = $this;
        $promise = $this->prophesize(PromiseInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $client->sendAsync(Argument::type(RequestInterface::class), [])
            ->shouldBeCalledTimes(1)
            ->will(function (array $args) use ($phpunit, $promise) {
                $request = $args[0];
                $uri = $request->getUri();
                $phpunit->assertEquals('key=apikey123', $uri->getQuery());

                return $promise;
            })
        ;

        $apiKeyClient = new ApiKeyClient($apiKey, $client->reveal());
        $apiKeyClient->sendAsync(new Request('GET', 'http://foo/'));
    }
}
