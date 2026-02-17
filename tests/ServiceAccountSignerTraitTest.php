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

namespace Google\Auth\Tests;

use Google\Auth\ServiceAccountSignerTrait;
use PHPUnit\Framework\TestCase;

class ServiceAccountSignerTraitTest extends TestCase
{
    const STRING_TO_SIGN = 'hello world';

    private $signedString = [
        'hlUvgzpJQm5mkIG8EWb4YiyGBsKN/VTsR8JOEfjh9je6bwaufgW3eAoAzFPY/4phMCAy7',
        'OOl0Q+jrPMmkL9BpevbJRUG4g3fYBkVcWqpwvSZVbNW889DZiMyKf+NWb86KlLqC1o8aE',
        'Iwh16L6rvXdg5iYA5/j/y2QYA7kACua/difsCVEpSv+XBZSzsRyMR4J6P2S52SUpyJkXU',
        'S79uifXPLV2Lf3qeFvnqqmqG5FTg5VH6Pr7qhGmenmP9Am5YBQxX1XaM9J3tvViA+yO9H',
        'ctvFXsGBXJyS5G2FIhHVCsGG3ScWvWlUv1HHY0QLwKvJaIusj+Q+r1aN0sOaiSE1jg==',
    ];

    /**
     * @dataProvider useOpenSsl
     */
    public function testSignBlob($useOpenSsl)
    {
        $trait = new ServiceAccountSignerTraitImpl(
            file_get_contents(__DIR__ . '/fixtures/fixtures1/private.pem')
        );

        $res = $trait->signBlob(self::STRING_TO_SIGN, $useOpenSsl);

        $this->assertEquals(implode('', $this->signedString), $res);
    }

    public function useOpenSsl()
    {
        return [[true], [false]];
    }
}

class ServiceAccountSignerTraitImpl
{
    use ServiceAccountSignerTrait;

    private $auth;

    public function __construct($signingKey)
    {
        $this->auth = new AuthStub();
        $this->auth->signingKey = $signingKey;
    }
}

class AuthStub
{
    public $signingKey;

    public function getSigningKey()
    {
        return $this->signingKey;
    }
}
