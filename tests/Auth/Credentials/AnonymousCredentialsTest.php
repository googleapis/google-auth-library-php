<?php
/*
 * Copyright 2018 Google Inc.
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

namespace Google\Auth\Credentials\Tests;

use Google\Auth\Credentials\AnonymousCredentials;
use PHPUnit\Framework\TestCase;

/**
 * @group credentials
 *
 * @internal
 * @covers \Google\Auth\Credentials\AnonymousCredentials
 */
class AnonymousCredentialsTest extends TestCase
{
    public function testFetchAuthToken()
    {
        $credentials = new AnonymousCredentials();
        $this->assertEquals(
            ['access_token' => ''],
            $credentials->fetchAuthToken()
        );
    }

    public function testGetRequestMetadata()
    {
        $credentials = new AnonymousCredentials();
        $this->assertEquals(
            ['Authorization' => 'Bearer '],
            $credentials->getRequestMetadata()
        );
    }

    public function testGetQuotaProject()
    {
        $credentials = new AnonymousCredentials();
        $this->assertNull($credentials->getQuotaProject());
    }

    public function testGetProjectId()
    {
        $credentials = new AnonymousCredentials();
        $this->assertNull($credentials->getProjectId());
    }
}
