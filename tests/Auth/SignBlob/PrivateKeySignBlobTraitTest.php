<?php
/*
 * Copyright 2019 Google LLC
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

namespace Google\Auth\SignBlob\Tests;

use Google\Auth\SignBlob\PrivateKeySignBlobTrait;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @covers \Google\Auth\SignBlob\PrivateKeySignBlobTrait
 */
class PrivateKeySignBlobTraitTest extends TestCase
{
    private const STRING_TO_SIGN = 'hello world';

    private $signedString = [
        'ZPeNGA9xcqwMQ7OEfNdLuwgxO+rJ59mhetIZrqWncY0uv+IZN0',
        'T4F3mg2sJVRD3awswFFdfMK20Xrnqo0dr8XdlgOkS5NIG38yrDagXsBf1ypAfji1sm22',
        'UCyxkaPdB6eRczMXwJReu6q4LCJmx/Xr46kU/ZDNhrBkj6vjoD8yo=',
    ];

    public function testSignBlob()
    {
        $trait = new PrivateKeySignBlobTraitImpl(
            file_get_contents(__DIR__ . '/../fixtures/private.pem')
        );

        $res = $trait->signBlob(self::STRING_TO_SIGN);

        $this->assertEquals(implode('', $this->signedString), $res);
    }
}

class PrivateKeySignBlobTraitImpl
{
    use PrivateKeySignBlobTrait;

    private $signingKey;

    public function __construct($signingKey)
    {
        $this->signingKey = $signingKey;
    }

    public function signBlob($stringToSign)
    {
        return $this->signBlobWithPrivateKey($stringToSign, $this->signingKey);
    }
}
