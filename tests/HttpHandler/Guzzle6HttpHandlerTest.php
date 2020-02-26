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

namespace Google\Auth\Tests\HttpHandler;

use Google\Auth\HttpHandler\Guzzle6HttpHandler;
use Google\Auth\Tests\BaseTest;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Psr7\Response;
use Prophecy\Argument;

/**
 * @group http-handler
 */
class Guzzle6HttpHandlerTest extends BaseTest
{
    public function setUp()
    {
        $this->onlyGuzzle6();

        $this->mockRequest = $this->prophesize('Psr\Http\Message\RequestInterface');
        $this->mockClient = $this->prophesize('GuzzleHttp\Client');
    }

    public function testSuccessfullySendsRequest()
    {
        $this->mockClient->send(Argument::type('Psr\Http\Message\RequestInterface'), [])
            ->willReturn(new Response(200));

        $handler = new Guzzle6HttpHandler($this->mockClient->reveal());
        $response = $handler($this->mockRequest->reveal());
        $this->assertInstanceOf('Psr\Http\Message\ResponseInterface', $response);
    }

    public function testSuccessfullySendsRequestAsync()
    {
        $this->mockClient->sendAsync(Argument::type('Psr\Http\Message\RequestInterface'), [])
            ->willReturn(new Promise(function () use (&$promise) {
                return $promise->resolve(new Response(200, [], 'Body Text'));
            }));

        $handler = new Guzzle6HttpHandler($this->mockClient->reveal());
        $promise = $handler->async($this->mockRequest->reveal());
        $response = $promise->wait();
        $this->assertInstanceOf('Psr\Http\Message\ResponseInterface', $response);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Body Text', (string) $response->getBody());
    }
}
