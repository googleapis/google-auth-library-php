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

namespace Google\Auth\Tests\Middleware;

use Google\Auth\Middleware\ScopedAccessTokenMiddleware;
use Google\Auth\Tests\BaseTest;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use Prophecy\Argument;

class ScopedAccessTokenMiddlewareTest extends BaseTest
{
    const TEST_SCOPE = 'https://www.googleapis.com/auth/cloud-taskqueue';

    private $tokenFunc;
    private $mockRequest;

    protected function setUp()
    {
        $this->onlyGuzzle6And7();

        $this->tokenFunc = new TokenFuncImplementation;
        $this->mockRequest = $this->prophesize('GuzzleHttp\Psr7\Request');
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testRequiresScopeAsAStringOrArray()
    {
        new ScopedAccessTokenMiddleware($this->tokenFunc, new \stdClass());
    }

    public function testAddsTheTokenAsAnAuthorizationHeader()
    {
        $wantToken = $this->tokenFunc->value();

        $this->mockRequest->withHeader('authorization', 'Bearer ' . $wantToken)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockRequest->reveal());

        // Run the test
        $middleware = new ScopedAccessTokenMiddleware($this->tokenFunc, self::TEST_SCOPE);
        $mock = new MockHandler([new Response(200)]);
        $callable = $middleware($mock);
        $callable($this->mockRequest->reveal(), ['auth' => 'scoped']);
    }

    public function testCachesToken()
    {
        $wantToken = $this->tokenFunc->value();

        $this->mockRequest->withHeader('authorization', 'Bearer ' . $wantToken)
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockRequest->reveal());

        // Run the test
        $middleware = new ScopedAccessTokenMiddleware(
            $this->tokenFunc,
            self::TEST_SCOPE,
        );

        $request  = $this->mockRequest->reveal();
        $handler  = new MockHandler([new Response(200), new Response(200)]);
        $callable = $middleware($handler);

        $callable($request, ['auth' => 'scoped']);
        $callable($request, ['auth' => 'scoped']);
    }

    public function testOnlyTouchesWhenAuthConfigScoped()
    {
        $this->mockRequest->withHeader()->shouldNotBeCalled();

        // Run the test
        $middleware = new ScopedAccessTokenMiddleware($this->tokenFunc, self::TEST_SCOPE);
        $mock = new MockHandler([new Response(200)]);
        $callable = $middleware($mock);
        $callable($this->mockRequest->reveal(), ['auth' => 'not_scoped']);
    }
}

class TokenFuncImplementation
{
    private $iteration;

    public function __construct($iteration = 0)
    {
        $this->iteration = $iteration;
    }

    public function __invoke($unused_scopes) {
        $value = $this->value();

        $this->iteration++;

        return $value;
    }

    public function value() {
        return "auth-token-{$this->iteration}";
    }
}
