<?php
/**
 * Copyright 2024 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Google\Auth\Tests\Logging;

use Google\Auth\Logging\LoggingTrait;
use Google\Auth\Logging\RpcLogEvent;
use Google\Auth\Logging\StdOutLogger;
use Google\Auth\Tests\BaseTest;
use Psr\Log\LoggerInterface;

class LoggingTraitTest extends BaseTest
{
    private $loggerContainer;

    public function setUp(): void
    {
        $this->loggerContainer = new class() {
            use LoggingTrait {
                logRequest as public;
                logResponse as public;
            }

            private LoggerInterface $logger;

            public function __construct()
            {
                $this->logger = new StdOutLogger();
            }
        };
    }

    public function testLogRequest()
    {
        $event = $this->getNewLogEvent();
        $this->loggerContainer->logRequest($event);

        $buffer = $this->getActualOutput();
        $jsonParsed = json_decode($buffer, true);

        $this->assertEquals($event->timestamp, $jsonParsed['timestamp']);
        $this->assertEquals($event->processId, $jsonParsed['processId']);
        $this->assertEquals($event->method, $jsonParsed['jsonPayload']['request.method']);
        $this->assertEquals($event->url, $jsonParsed['jsonPayload']['request.url']);
        $this->assertEquals($event->headers, $jsonParsed['jsonPayload']['request.headers']);
        $this->assertArrayHasKey('request.jwt', $jsonParsed['jsonPayload']);
    }

    public function testRequestWithoutJwtShouldNotPrintAJwt()
    {
        $event = $this->getNewLogEvent();
        $event->headers = ['no jwt' => true];
        $this->loggerContainer->logRequest($event);

        $buffer = $this->getActualOutput();
        $jsonParsed = json_decode($buffer, true);

        $this->assertArrayNotHasKey('request.jwt', $jsonParsed['jsonPayload']);
    }

    public function testLogResponse()
    {
        $event = $this->getNewLogEvent();
        $event->headers = ['Thisis' => 'a header'];
        $this->loggerContainer->logResponse($event);

        $buffer = $this->getActualOutput();

        $parsedDebugEvent = json_decode($buffer, true);
        $this->assertEquals($event->processId, $parsedDebugEvent['processId']);
        $this->assertEquals($event->requestId, $parsedDebugEvent['requestId']);
        $this->assertEquals($event->headers, $parsedDebugEvent['jsonPayload']['response.headers']);
    }

    private function getNewLogEvent(): RpcLogEvent
    {
        $event = new RpcLogEvent();
        $event->processId = 123;
        $event->method = 'get';
        $event->url = 'test.com';
        $event->headers = [
            'header1' => 'test',
            'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cThIIoDvwdueQB468K5xDc5633seEFoqwxjF_xSJyQQ'
        ];
        $event->payload = json_encode(['param' => 'test']);
        $event->status = 200;
        $event->retryAttempt = 0;
        $event->rpcName = 'Rpc NameTest';
        $event->serviceName = 'Service Name';
        $event->requestId = 321;
        $event->latency = 555;

        return $event;
    }
}
