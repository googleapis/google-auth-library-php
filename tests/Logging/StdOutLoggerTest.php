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

use Exception;
use Google\Auth\Logging\StdOutLogger;
use Google\Auth\Tests\BaseTest;
use Psr\Log\LogLevel;

class StdOutLoggerTest extends BaseTest
{
    public function testConstructsWithAnIncorrectLevelThrowsException()
    {
        $this->expectException(Exception::class);
        new StdOutLogger('invalid level');
    }

    public function testLoggingOnSameLevelWritesToStdOut()
    {
        ob_start();

        $logger = new StdOutLogger(LogLevel::DEBUG);
        $expectedString = 'test';
        $logger->debug($expectedString);
        $buffer = ob_get_contents();

        $this->assertEquals($expectedString . "\n", $buffer);

        ob_end_clean();
    }

    public function testLoggingOnHigherLeverWritesToStdOut()
    {
        ob_start();

        $logger = new StdOutLogger(LogLevel::WARNING);
        $expectedString = 'test';
        $logger->error($expectedString);
        $buffer = ob_get_contents();

        $this->assertEquals($expectedString . "\n", $buffer);

        ob_end_clean();
    }

    public function testLoggingOnLowerLeverDoesNotWriteToStdOut()
    {
        ob_start();

        $logger = new StdOutLogger(LogLevel::WARNING);
        $expectedString = 'test';
        $logger->debug($expectedString);
        $buffer = ob_get_contents();

        $this->assertEmpty($buffer);

        ob_end_clean();
    }
}
