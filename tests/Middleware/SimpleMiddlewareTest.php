<?php
/*
 * Copyright 2010 Google Inc.
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

namespace Google\Auth\Tests\Middleware;

use Google\Auth\Middleware\SimpleMiddleware;
use Google\Auth\Tests\BaseTest;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\UriInterface;

class SimpleMiddlewareTest extends BaseTest
{
    use ProphecyTrait;

    private $mockRequest;

    /**
     * @todo finish
     */
    protected function setUp(): void
    {
        $this->mockRequest = $this->prophesize(Request::class);
    }

    public function testApiKey()
    {
        $testKey = 'foo';
        $params = Query::build(['key' => $testKey]);

        $mockUri = $this->prophesize(UriInterface::class);
        $mockUri->getQuery()
            ->shouldBeCalledTimes(1)
            ->willReturn('');
        $mockUri->withQuery($params)
            ->shouldBeCalledTimes(1)
            ->willReturn($mockUri->reveal());
        $this->mockRequest->getUri()
            ->shouldBeCalledTimes(2)
            ->willReturn($mockUri->reveal());
        $this->mockRequest->withUri($mockUri->reveal())
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockRequest->reveal());

        $middleware = new SimpleMiddleware(['key' => $testKey]);
        $mock = new MockHandler([new Response(200)]);
        $callable = $middleware($mock);
        $callable($this->mockRequest->reveal(), ['auth' => 'simple']);
    }
}
