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

namespace Google\Auth\Tests\Credentials;

use Google\Auth\Credentials\IAMCredentials;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * @group credentials
 * @group credentials-iam
 */
class IAMConstructorTest extends TestCase
{
    public function testShouldFailIfSelectorIsNotString()
    {
        $this->expectException(InvalidArgumentException::class);

        $notAString = new \stdClass();
        $iam = new IAMCredentials(
            $notAString,
            ''
        );
    }

    public function testShouldFailIfTokenIsNotString()
    {
        $this->expectException(InvalidArgumentException::class);

        $notAString = new \stdClass();
        $iam = new IAMCredentials(
            '',
            $notAString
        );
    }

    public function testInitializeSuccess()
    {
        $this->assertNotNull(
            new IAMCredentials('iam-selector', 'iam-token')
        );
    }
}

class IAMUpdateMetadataCallbackTest extends TestCase
{
    public function testUpdateMetadataFunc()
    {
        $selector = 'iam-selector';
        $token = 'iam-token';
        $iam = new IAMCredentials(
            $selector,
            $token
        );

        $update_metadata = $iam->getUpdateMetadataFunc();
        $this->assertTrue(is_callable($update_metadata));

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = ['foo' => 'bar']
        );
        $this->assertArrayHasKey(IAMCredentials::SELECTOR_KEY, $actual_metadata);
        $this->assertEquals(
            $actual_metadata[IAMCredentials::SELECTOR_KEY],
            $selector
        );
        $this->assertArrayHasKey(IAMCredentials::TOKEN_KEY, $actual_metadata);
        $this->assertEquals(
            $actual_metadata[IAMCredentials::TOKEN_KEY],
            $token
        );
    }
}
