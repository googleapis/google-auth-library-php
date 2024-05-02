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

namespace Google\Auth\Tests;

use Google\Auth\MetricsTrait;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;

class MetricsTraitTest extends TestCase
{
    use ProphecyTrait;

    private $impl;

    public function setUp(): void
    {
        $this->impl = new class() {
            use MetricsTrait{
                getVersion as public;
                getMetricsHeader as public;
            }
        };
    }

    public function testGetVersion()
    {
        $actualVersion = $this->impl::getVersion();
        $this->assertStringMatchesFormat('%d.%d.%d', $actualVersion);
    }

    /**
     * @dataProvider metricsHeaderCases
     */
    public function testGetMetricsHeader($credType, $authRequestType, $expected)
    {
        $headerValue = $this->impl::getMetricsHeader($credType, $authRequestType);
        $this->assertStringMatchesFormat('gl-php/%s auth/%s ' . $expected, $headerValue);
    }

    public function metricsHeaderCases()
    {
        return [
            ['foo', '', 'cred-type/foo'],
            ['', 'bar', 'auth-request-type/bar'],
            ['foo', 'bar', 'auth-request-type/bar cred-type/foo']
        ];
    }
}
