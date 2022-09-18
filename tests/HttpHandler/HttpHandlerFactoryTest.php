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

use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use Google\Auth\Tests\BaseTest;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use ReflectionClass;

class HttpHandlerFactoryTest extends BaseTest
{
    public function testBuildsGuzzle6Handler()
    {
        $this->onlyGuzzle6();

        HttpClientCache::setHttpClient(null);
        $handler = HttpHandlerFactory::build();
        $this->assertInstanceOf('Google\Auth\HttpHandler\Guzzle6HttpHandler', $handler);
    }

    public function testBuildsGuzzle7Handler()
    {
        $this->onlyGuzzle7();

        HttpClientCache::setHttpClient(null);
        $handler = HttpHandlerFactory::build();
        $this->assertInstanceOf('Google\Auth\HttpHandler\Guzzle7HttpHandler', $handler);
    }

    public function testBuildsGuzzle7HandlerWithExtendedTruncation()
    {
        $this->onlyGuzzle7();

        // Guzzle defaults to 120 characters. We expect to see our message truncated at 240
        $defaultTruncatedLength = 240;
        $longMessage = str_repeat('x', $defaultTruncatedLength + 1);
        $expectedMessage = str_repeat('x', $defaultTruncatedLength) . ' (truncated...)';
        $this->expectException(RequestException::class);
        $this->expectExceptionMessage($expectedMessage);

        // Create a mock error response with a long message
        $newStack = HandlerStack::create(new MockHandler([
            new Response(500, [], $longMessage),
        ]));

        // Get access to the default middleware stack so we can add it to our mock handler
        $handler = HttpHandlerFactory::build();
        $clientProp = (new ReflectionClass($handler))->getParentClass()->getProperty('client');
        $clientProp->setAccessible(true);

        $handlerStack = $clientProp->getValue($handler)->getConfig('handler');
        $stackProp = (new ReflectionClass($handlerStack))->getProperty('stack');
        $stackProp->setAccessible(true);

        foreach ($stackProp->getValue($handlerStack) as $idx => $middleware) {
            $newStack->push($middleware[0], $middleware[1]);
        }

        $client = new Client(['handler' => $newStack]);
        $client->request('GET', '/');
    }
}
