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

namespace Google\Auth\Tests;

use Google\Auth\Compute;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @covers \Google\Auth\Compute
 */
class ComputeTest extends TestCase
{
    public function testOnComputeMetadataFlavorHeader()
    {
        $hasHeader = false;
        $httpClient = httpClientFromCallable(
            function ($request) use (&$hasHeader) {
                $hasHeader = 'Google' === $request->getHeaderLine('Metadata-Flavor');

                return new Response(200, ['Metadata-Flavor' => 'Google']);
            }
        );

        $onCompute = Compute::onCompute($httpClient);
        $this->assertTrue($hasHeader);
        $this->assertTrue($onCompute);
    }

    public function testOnComputeIsFalseOnClientErrorStatus()
    {
        // simulate retry attempts by returning multiple 400s
        $httpClient = httpClientWithResponses([
            new Response(400),
            new Response(400),
            new Response(400),
        ]);
        $this->assertFalse(Compute::onCompute($httpClient));
    }

    public function testOnComputeIsFalseOnServerErrorStatus()
    {
        // simulate retry attempts by returning multiple 500s
        $httpClient = httpClientWithResponses([
            new Response(500),
            new Response(500),
            new Response(500),
        ]);
        $this->assertFalse(Compute::onCompute($httpClient));
    }

    public function testOnComputeIsFalseOnOkStatusWithoutExpectedHeader()
    {
        $httpClient = httpClientWithResponses([
            new Response(200),
        ]);
        $this->assertFalse(Compute::onCompute($httpClient));
    }

    public function testOnComputeIsOkIfGoogleIsTheFlavor()
    {
        $httpClient = httpClientWithResponses([
            new Response(200, ['Metadata-Flavor' => 'Google']),
        ]);
        $this->assertTrue(Compute::onCompute($httpClient));
    }

    /**
     * @runInSeparateProcess
     */
    public function testOnAppEngineFlexIsFalseWhenGaeInstanceIsEmpty()
    {
        putenv('GAE_INSTANCE=');
        $this->assertFalse(Compute::onAppEngineFlexible());
    }

    /**
     * @runInSeparateProcess
     */
    public function testOnAppEngineFlexIsFalseWhenGaeInstanceIsNotAef()
    {
        putenv('GAE_INSTANCE=not-aef-20180313t154438');
        $this->assertFalse(Compute::onAppEngineFlexible());
    }

    /**
     * @runInSeparateProcess
     */
    public function testOnAppEngineFlexIsTrueWhenGaeInstanceHasAefPrefix()
    {
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $this->assertTrue(Compute::onAppEngineFlexible());
    }
}
