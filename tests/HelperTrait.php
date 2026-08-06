<?php
/*
 * Copyright 2026 Google Inc.
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

use Google\Auth\HttpHandler\Guzzle7HttpHandler;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;

trait HelperTrait
{
    private function getHandler(array $mockResponses = []): Guzzle7HttpHandler
    {
        $mock = new MockHandler($mockResponses);
        $handler = HandlerStack::create($mock);
        $client = new Client(["handler" => $handler]);

        return new Guzzle7HttpHandler($client);
    }

    private function setHomeEnv(?string $value): void
    {
        $assigment = sprintf(
            "%s%s%s",
            PHP_OS_FAMILY === "Windows" ? "APPDATA" : "HOME",
            $value === null ? "" : "=",
            (string) $value
        );

        putenv($assigment);
    }

    private function skipResidencyCheck(bool $skip = true): void
    {
        $prop = new \ReflectionProperty(
            \Google\Auth\Credentials\GCECredentials::class,
            'checkResidency'
        );
        $prop->setValue(null, !$skip);
    }
}
