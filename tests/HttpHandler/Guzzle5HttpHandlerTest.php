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

namespace Google\Auth\Tests;

use Composer\Autoload\ClassLoader;
use Exception;
use Google\Auth\HttpHandler\Guzzle5HttpHandler;
use GuzzleHttp\Message\FutureResponse;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Ring\Future\CompletedFutureValue;

class Guzzle5HttpHandlerTest extends BaseTest
{
    public function setUp()
    {
        $this->onlyGuzzle5();

        $this->mockPsr7Request =
            $this
                ->getMockBuilder('Psr\Http\Message\RequestInterface')
                ->getMock();
        $this->mockRequest =
            $this
                ->getMockBuilder('GuzzleHttp\Message\RequestInterface')
                ->getMock();
        $this->mockClient =
            $this
                ->getMockBuilder('GuzzleHttp\Client')
                ->disableOriginalConstructor()
                ->getMock();
        $this->mockFuture =
            $this
                ->getMockBuilder('GuzzleHttp\Ring\Future\FutureInterface')
                ->disableOriginalConstructor()
                ->getMock();
    }

    public function testSuccessfullySendsRequest()
    {
        $this->mockClient
            ->expects($this->any())
            ->method('send')
            ->will($this->returnValue(new Response(200)));
        $this->mockClient
            ->expects($this->any())
            ->method('createRequest')
            ->will($this->returnValue($this->mockRequest));

        $handler = new Guzzle5HttpHandler($this->mockClient);
        $response = $handler($this->mockPsr7Request);
        $this->assertInstanceOf('Psr\Http\Message\ResponseInterface', $response);
    }

    public function testAsyncWithoutGuzzlePromiseThrowsException()
    {
        // Pretend the promise library doesn't exist
        foreach (spl_autoload_functions() as $function) {
            if ($function[0] instanceof ClassLoader) {
                $newAutoloader = clone $function[0];
                $newAutoloader->setPsr4('GuzzleHttp\\Promise\\', '/tmp');
                spl_autoload_register($newAutoloadFunc = [$newAutoloader, 'loadClass']);
                spl_autoload_unregister($previousAutoloadFunc = $function);
            }
        }
        $this->mockClient
            ->expects($this->any())
            ->method('send')
            ->will($this->returnValue(new FutureResponse($this->mockFuture)));
        $this->mockClient
            ->expects($this->any())
            ->method('createRequest')
            ->will($this->returnValue($this->mockRequest));

        $handler = new Guzzle5HttpHandler($this->mockClient);
        $errorThrown = false;
        try {
            $handler->async($this->mockPsr7Request);
        } catch (Exception $e) {
            $this->assertEquals(
                'Install guzzlehttp/promises to use async with Guzzle 5',
                $e->getMessage()
            );
            $errorThrown = true;
        }

        // Restore autoloader before assertion (in case it fails)
        spl_autoload_register($previousAutoloadFunc);
        spl_autoload_unregister($newAutoloadFunc);

        $this->assertTrue($errorThrown);
    }

    public function testSuccessfullySendsRequestAsync()
    {
        $this->mockClient
            ->expects($this->any())
            ->method('send')
            ->will($this->returnValue(new FutureResponse(
                new CompletedFutureValue(new Response(200))
            )));
        $this->mockClient
            ->expects($this->any())
            ->method('createRequest')
            ->will($this->returnValue($this->mockRequest));

        $handler = new Guzzle5HttpHandler($this->mockClient);
        $promise = $handler->async($this->mockPsr7Request);
        $this->assertInstanceOf('Psr\Http\Message\ResponseInterface', $promise->wait());
    }

    /**
     * @expectedException GuzzleHttp\Promise\RejectionException
     * @expectedExceptionMessage This is a test rejection message
     */
    public function testPromiseHandlesError()
    {
        $this->mockClient
            ->expects($this->any())
            ->method('send')
            ->will($this->returnValue(new FutureResponse(
                (new CompletedFutureValue(new Response(200)))
                    ->then(function () {
                        throw new Exception('This is a test rejection message');
                    })
            )));
        $this->mockClient
            ->expects($this->any())
            ->method('createRequest')
            ->will($this->returnValue($this->mockRequest));

        $handler = new Guzzle5HttpHandler($this->mockClient);
        $promise = $handler->async($this->mockPsr7Request);
        $promise->wait();
    }
}
