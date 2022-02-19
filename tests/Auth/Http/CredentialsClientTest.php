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

use Google\Auth\Credentials\CredentialsInterface;
use Google\Auth\Http\CredentialsClient;
use Google\Http\ClientInterface;
use Google\Http\PromiseInterface;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Http\Message\RequestInterface;

/**
 * @internal
 * @covers \Google\Auth\Http\CredentialsClient
 */
class CredentialsClientTest extends TestCase
{
    public function testSend()
    {
        $phpunit = $this;
        $credentials = $this->prophesize(CredentialsInterface::class);
        $credentials->getRequestMetadata()
            ->shouldBeCalledTimes(1)
            ->willReturn(['Authorization' => 'Bearer 123'])
        ;

        $client = $this->prophesize(ClientInterface::class);
        $client->send(Argument::type(RequestInterface::class), [])
            ->will(function (array $args) use ($phpunit) {
                $request = $args[0];
                $phpunit->assertEquals(
                    'Bearer 123',
                    $request->getHeaderLine('Authorization')
                );

                return new Response(200);
            })
        ;

        $credentialsClient = new CredentialsClient(
            $credentials->reveal(),
            $client->reveal()
        );
        $credentialsClient->send(new Request('GET', 'http://foo/'));
    }

    public function testSendAsync()
    {
        $phpunit = $this;
        $credentials = $this->prophesize(CredentialsInterface::class);
        $credentials->getRequestMetadata()
            ->shouldBeCalledTimes(1)
            ->willReturn(['Authorization' => 'Bearer 123'])
        ;
        $promise = $this->prophesize(PromiseInterface::class);

        $client = $this->prophesize(ClientInterface::class);
        $client->sendAsync(Argument::type(RequestInterface::class), [])
            ->will(function (array $args) use ($phpunit, $promise) {
                $request = $args[0];
                $phpunit->assertEquals(
                    'Bearer 123',
                    $request->getHeaderLine('Authorization')
                );

                return $promise;
            })
        ;

        $credentialsClient = new CredentialsClient(
            $credentials->reveal(),
            $client->reveal()
        );
        $credentialsClient->sendAsync(new Request('GET', 'http://foo/'));
    }
}
