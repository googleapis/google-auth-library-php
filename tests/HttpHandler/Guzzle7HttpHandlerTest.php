<?php
/*
 * Copyright 2020 Google Inc.
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

use Google\Auth\HttpHandler\Guzzle7HttpHandler;
use Google\Auth\Logging\StdOutLogger;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Prophecy\Argument;

/**
 * @group http-handler
 */
class Guzzle7HttpHandlerTest extends Guzzle6HttpHandlerTest
{
    public function setUp(): void
    {
        $this->onlyGuzzle7();

        $this->client = $this->prophesize('GuzzleHttp\ClientInterface');
        $this->handler = new Guzzle7HttpHandler($this->client->reveal());
    }

    public function testLoggerGetsCalledIfLoggerIsPassed()
    {
        $requestPromise = new Promise(function () use (&$requestPromise) {
            $response = new Response(200);
            $requestPromise->resolve($response);
        });

        $mockLogger = $this->prophesize(StdOutLogger::class);
        $mockLogger->debug(Argument::cetera())
            ->shouldBeCalledTimes(2);

        $this->client->sendAsync(Argument::cetera())
            ->willReturn($requestPromise);

        $request = new Request('GET', 'https://domain.tld');
        $options = ['key' => 'value'];

        $handler = new Guzzle7HttpHandler($this->client->reveal(), $mockLogger->reveal());
        $handler->async($request, $options)->wait();
    }

    public function testLoggerDoesNotGetsCalledIfLoggerIsNotPassed()
    {
        $requestPromise = new Promise(function () use (&$requestPromise) {
            $response = new Response(200);
            $requestPromise->resolve($response);
        });

        $this->client->sendAsync(Argument::cetera())
            ->willReturn($requestPromise)
            ->shouldBeCalledTimes(1);

        $request = new Request('GET', 'https://domain.tld');
        $options = ['key' => 'value'];

        $handler = new Guzzle7HttpHandler($this->client->reveal());
        $handler->async($request, $options)->wait();

        $this->expectOutputString('');
    }
}
