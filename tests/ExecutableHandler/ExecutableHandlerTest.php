<?php
/*
 * Copyright 2024 Google Inc.
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

namespace Google\Auth\Tests\ExecutableHandler;

use Google\Auth\ExecutableHandler\ExecutableHandler;
use Google\Auth\ExecutableHandler\ExecutableResponseError;
use PHPUnit\Framework\TestCase;

class ExecutableHandlerTest extends TestCase
{
    public function testEnvironmentVariables()
    {
        $handler = new ExecutableHandler(['ENV_VAR_1' => 'foo', 'ENV_VAR_2' => 'bar']);
        $this->assertEquals(0, $handler('echo $ENV_VAR_1'));
        $this->assertEquals("foo\n", $handler->getOutput());

        $this->assertEquals(0, $handler('echo $ENV_VAR_2'));
        $this->assertEquals("bar\n", $handler->getOutput());
    }

    public function testTimeoutMs()
    {
        $handler = new ExecutableHandler([], 300);
        $this->assertEquals(0, $handler('sleep "0.2"'));
    }

    public function testTimeoutMsExceeded()
    {
        $this->expectException(ExecutableResponseError::class);
        $this->expectExceptionMessage('The executable failed to finish within the timeout specified.');

        $handler = new ExecutableHandler([], 100);
        $handler('sleep "0.2"');
    }

    public function testErrorOutputIsReturnedAsOutput()
    {
        $handler = new ExecutableHandler();
        $this->assertEquals(0, $handler('echo "Bad Response." >&2'));
        $this->assertEquals("Bad Response.\n", $handler->getOutput());
    }
}
