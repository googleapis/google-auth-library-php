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

use Google\Auth\Logging\LogEvent;
use Google\Auth\Logging\LoggingTrait;
use Google\Auth\Logging\StdOutLogger;
use Google\Auth\Tests\BaseTest;
use Psr\Log\LoggerInterface;

class LoggingTraitTest extends BaseTest
{
    private MockClassWithLogger $loggerContainer;

    public function setUp(): void
    {
        $this->loggerContainer = new MockClassWithLogger();
    }

    public function testLogRequest()
    {
        ob_start();

        $event = $this->getNewLogEvent();
        $this->loggerContainer->logRequestEvent($event);

        $buffer = ob_get_contents();
        ob_end_clean();
        $jsonParsed = json_decode($buffer, true);

        $this->assertEquals($event->timestamp, $jsonParsed['timestamp']);
        $this->assertEquals($event->clientId, $jsonParsed['clientId']);
        $this->assertEquals($event->method, $jsonParsed['jsonPayload']['request.method']);
        $this->assertEquals($event->url, $jsonParsed['jsonPayload']['request.url']);
        $this->assertEquals($event->headers, $jsonParsed['jsonPayload']['request.headers']);
        $this->assertArrayHasKey('request.jwt', $jsonParsed['jsonPayload']);
    }

    public function testRequestWithoutJwtShouldNotPrintAJwt()
    {
        ob_start();

        $event = $this->getNewLogEvent();
        $event->headers = ['no jwt' => true];
        $this->loggerContainer->logRequestEvent($event);

        $buffer = ob_get_contents();
        ob_end_clean();
        $jsonParsed = json_decode($buffer, true);

        $this->assertArrayNotHasKey('request.jwt', $jsonParsed['jsonPayload']);
    }

    public function testLogResponse()
    {
        ob_start();

        $event = $this->getNewLogEvent();
        $this->loggerContainer->logResponseEvent($event);

        $buffer = ob_get_contents();
        ob_end_clean();

        $buffer = str_replace("\n", '', $buffer);

        // The LogResponse method logs two evnets, one for info and one for debug.
        [$debugEvent, $infoEvent] = explode('}{', $buffer);
        $debugEvent .= '}';
        $infoEvent = '{' . $infoEvent;

        $parsedDebugEvent = json_decode($debugEvent, true);
        $this->assertEquals($event->clientId, $parsedDebugEvent['clientId']);
        $this->assertEquals($event->requestId, $parsedDebugEvent['requestId']);
        $this->assertEquals($event->headers, $parsedDebugEvent['jsonPayload']['response.headers']);

        $parsedInfoEvent = json_decode($infoEvent, true);
        $this->assertEquals($event->status, $parsedInfoEvent['jsonPayload']['response.status']);
    }

    private function getNewLogEvent(): LogEvent
    {
        $event = new LogEvent();
        $event->clientId = 123;
        $event->method = 'get';
        $event->url = 'test.com';
        $event->headers = [
            'header1' => 'test',
            'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cThIIoDvwdueQB468K5xDc5633seEFoqwxjF_xSJyQQ'
        ];
        $event->payload = ['param' => 'test'];
        $event->status = 200;
        $event->retryAttempt = 0;
        $event->rpcName = 'Rpc NameTest';
        $event->serviceName = 'Service Name';
        $event->requestId = 321;
        $event->latency = 555;

        return $event;
    }
}

class MockClassWithLogger
{
    use LoggingTrait;
    private LoggerInterface $logger;

    public function __construct()
    {
        $this->logger = new StdOutLogger();
    }

    public function logRequestEvent(LogEvent $event): void
    {
        $this->logRequest($event);
    }

    public function logResponseEvent(LogEvent $event): void
    {
        $this->logResponse($event);
    }
}
