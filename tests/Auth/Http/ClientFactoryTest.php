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

use Google\Auth\Http\ClientFactory;
use Google\Http\Client\GuzzleClient;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @covers \Google\Auth\Http\ClientFactory
 */
class ClientFactoryTest extends TestCase
{
    public function testBuildsGuzzleClient()
    {
        $client = ClientFactory::build();
        $this->assertInstanceOf(GuzzleClient::class, $client);

        $reflection = new \ReflectionClass($client);
        $property = $reflection->getProperty('client');
        $property->setAccessible(true);
        $guzzleClient = $property->getValue($client);

        if (defined(sprintf('%s::MAJOR_VERSION', get_class($guzzleClient)))) {
            // Assert Guzzle 7
            $this->assertEquals(7, $guzzleClient::MAJOR_VERSION);
        } else {
            $version = $guzzleClient::VERSION;
            $this->assertEquals('6', $version[0]);
        }
    }
}
