<?php
/*
 * Copyright 2023 Google Inc.
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

namespace Google\Auth\Tests;

use Google\Auth\MetricsTrait;
use PHPUnit\Framework\TestCase;

class MetricsTraitTest extends TestCase
{
    // TODO: Find a way to get the auth version
    private const VERSION = '10.0.0';

    private $impl;
    private $phpAndAuthVersion;
    private $defaultForAccessTokenRequest;
    private $defaultForIdTokenRequest;
    public function setUp(): void
    {
        $this->impl = new MetricsTraitImplementation();
        $this->phpAndAuthVersion = 'gl-php/' . PHP_VERSION
            . ' auth/' . self::VERSION;
        $this->defaultForAccessTokenRequest = $this->phpAndAuthVersion
            . ' ' . $this->impl::$requestTypeAccessToken;
        $this->defaultForIdTokenRequest = $this->phpAndAuthVersion
            . ' ' . $this->impl::$requestTypeIdToken;
    }

    public function testGetPhpAndAuthLibVersion()
    {
        $this->assertEquals(
            $this->phpAndAuthVersion,
            $this->impl->getPhpAndAuthLibVersion()
        );
    }

    public function testGetDefaults()
    {
        // For access token
        $this->assertEquals(
            $this->defaultForAccessTokenRequest,
            $this->impl->getDefaults($isAccessTokenRequest = true)
        );

        // For identity token
        $this->assertEquals(
            $this->defaultForIdTokenRequest,
            $this->impl->getDefaults($isAccessTokenRequest = false)
        );
    }

    /**
     * @dataProvider getTokenRequestHeaderCases
     * @param bool $isAccessTokenRequest
     * @param string $credType
     * @param string $expected
     */
    public function testGetTokenRequestHeaders(
        bool $isAccessTokenRequest,
        string $credType,
        string $expected
    ) {
        $defaultHeader = $isAccessTokenRequest ?
            $this->defaultForAccessTokenRequest :
            $this->defaultForIdTokenRequest;
        $expectedResult = $defaultHeader . ' ' . $expected;

        $testMethodName = 'getTokenRequest' . $credType . 'Header';
        $this->assertEquals(
            $expectedResult,
            $this->impl->$testMethodName($isAccessTokenRequest)
        );
    }

    public function testGetMdsPingHeader()
    {
        $this->assertEquals(
            $this->phpAndAuthVersion . ' ' . $this->impl::$requestTypeMdsPing,
            $this->impl->getMdsPingHeader()
        );
    }

    public function getTokenRequestHeaderCases()
    {
        $impl = new MetricsTraitImplementation();
        return [
            [true, 'Mds', $impl::$credTypeSaMds],
            [false, 'Mds', $impl::$credTypeSaMds],
            [true, 'SaAssertion', $impl::$credTypeSaAssertion],
            [false, 'SaAssertion', $impl::$credTypeSaAssertion],
            [true, 'SaImpersonate', $impl::$credTypeSaImpersonate],
            [false, 'SaImpersonate', $impl::$credTypeSaImpersonate],
            [true, 'User', $impl::$credTypeUser],
            [false, 'User', $impl::$credTypeUser]
        ];
    }
}

class MetricsTraitImplementation
{
    use MetricsTrait {
        getDefaults as public;
    }
}
