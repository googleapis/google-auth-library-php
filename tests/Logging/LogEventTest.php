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
use Google\Auth\Tests\BaseTest;

class LogEventTest extends BaseTest
{
    public function testInstanceAddsTimestamp()
    {
        $item = new LogEvent();
        $this->assertNotNull($item->timestamp);
    }

    public function testConstructorWithoutParameterHasNoLatency()
    {
        $item = new LogEvent();
        $this->assertNull($item->latency);
    }

    public function testConstructorWithParameterHasLatencySet()
    {
        $item = new LogEvent(date(DATE_RFC3339));
        $this->assertNotNull($item->latency);
    }
}
