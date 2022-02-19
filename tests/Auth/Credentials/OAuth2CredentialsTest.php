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

use Google\Auth\Credentials\OAuth2Credentials;
use Google\Auth\OAuth2;
use LogicException;
use PHPUnit\Framework\TestCase;

/**
 * @group credentials
 *
 * @internal
 * @covers \Google\Auth\Credentials\OAuth2Credentials
 */
class OAuth2CredentialsTest extends TestCase
{
    public function testFetchAuthToken()
    {
        $oauth2 = $this->prophesize(OAuth2::class);
        $oauth2->fetchAuthToken()
            ->shouldBeCalledTimes(1)
            ->willReturn(['access_token' => '123'])
        ;
        $oauth2->getCacheKey()
            ->shouldBeCalledTimes(1)
            ->wilLReturn('abc')
        ;

        $credentials = new OAuth2Credentials($oauth2->reveal());
        $this->assertEquals(
            ['access_token' => '123'],
            $credentials->fetchAuthToken()
        );
    }

    public function testGetRequestMetadata()
    {
        $oauth2 = $this->prophesize(OAuth2::class);
        $oauth2->fetchAuthToken()
            ->shouldBeCalledTimes(1)
            ->willReturn(['access_token' => '123'])
        ;
        $oauth2->getCacheKey()
            ->shouldBeCalledTimes(1)
            ->wilLReturn('abc')
        ;

        $credentials = new OAuth2Credentials($oauth2->reveal());
        $this->assertEquals(
            ['Authorization' => 'Bearer 123'],
            $credentials->getRequestMetadata()
        );
    }

    public function testGetQuotaProject()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'getQuotaProject is not implemented for OAuth2 credentials'
        );

        $oauth2 = $this->prophesize(OAuth2::class);
        $credentials = new OAuth2Credentials($oauth2->reveal());
        $credentials->getQuotaProject();
    }

    public function testGetProjectId()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'getProjectId is not implemented for OAuth2 credentials'
        );

        $oauth2 = $this->prophesize(OAuth2::class);
        $credentials = new OAuth2Credentials($oauth2->reveal());
        $credentials->getProjectId();
    }
}
