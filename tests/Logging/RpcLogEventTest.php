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

use Google\Auth\Logging\RpcLogEvent;
use Google\Auth\Tests\BaseTest;

class RpcLogEventTest extends BaseTest
{
    public function testInstanceAddsTimestamp()
    {
        $item = new RpcLogEvent();
        $this->assertNotNull($item->timestamp);
    }

    public function testConstructorWithoutParameterHasNoLatency()
    {
        $item = new RpcLogEvent();
        $this->assertNull($item->latency);
    }

    public function testConstructorWithParameterHasLatencySet()
    {
        // We sustract 1000 ms to simulate a microtime 1000ms in the past
        $previousMicrotimeInMillis = (microtime(true) * 1000) - 1000;
        $item = new RpcLogEvent($previousMicrotimeInMillis);
        $this->assertNotNull($item->latency);

        // Adding a delta to the test due timing on how this executes
        $this->assertEqualsWithDelta(1000, $item->latency, 5);
    }
}