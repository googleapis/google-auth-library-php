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

namespace Google\Auth\Tests\Credentials;

use Google\Auth\Credentials\StaticCredentials;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * @group credentials
 * @group credentials-static
 */
class StaticCredentialsTest extends TestCase
{
    public function testFetchAuthTokenReturnsSuppliedToken()
    {
        $creds = new StaticCredentials('my-access-token');
        $token = $creds->fetchAuthToken();

        $this->assertEquals('my-access-token', $token['access_token']);
        $this->assertGreaterThan(time(), $token['expires_at']);
    }

    public function testFetchAuthTokenHonorsExpiresIn()
    {
        $before = time();
        $creds = new StaticCredentials('my-access-token', 120);
        $token = $creds->fetchAuthToken();

        $this->assertGreaterThanOrEqual($before + 120, $token['expires_at']);
        $this->assertLessThanOrEqual(time() + 120, $token['expires_at']);
    }

    public function testFetchAuthTokenIgnoresHttpHandler()
    {
        $creds = new StaticCredentials('my-access-token');
        $handlerCalled = false;
        $httpHandler = function () use (&$handlerCalled) {
            $handlerCalled = true;
        };

        $creds->fetchAuthToken($httpHandler);
        $this->assertFalse($handlerCalled);
    }

    public function testGetLastReceivedTokenMatchesFetch()
    {
        $creds = new StaticCredentials('my-access-token');
        $this->assertEquals($creds->fetchAuthToken(), $creds->getLastReceivedToken());
    }

    public function testGetCacheKeyIsStableAndTokenSpecific()
    {
        $creds = new StaticCredentials('my-access-token');
        $other = new StaticCredentials('another-token');

        $this->assertEquals($creds->getCacheKey(), (new StaticCredentials('my-access-token'))->getCacheKey());
        $this->assertNotEquals($creds->getCacheKey(), $other->getCacheKey());
    }

    public function testEmptyAccessTokenThrows()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The access token must not be empty');

        new StaticCredentials('');
    }
}
