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

namespace Google\Auth\Jwt\Tests;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Google\Auth\GoogleAuth;
use Google\Auth\Jwt\FirebaseJwtClient;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use ReflectionClass;
use Prophecy\Argument;
use UnexpectedValueException;

class FirebaseJwtClientTest extends TestCase
{
    /**
     * @dataProvider provideDecode
     */
    public function testDecode(
        array $payload,
        array $expectedException = null
    ) {
        // We cannot use mocks because Prophecy cannot mock static methods
        $jwt = new class() extends JWT {
            public static $payload;
            public static $expectedException;

            public static function decode($jwt, $key, array $allowed_algs = [])
            {
                if (self::$expectedException) {
                    $exceptionClass = self::$expectedException['class'];
                    $exceptionMessage = self::$expectedException['message'];
                    throw new $exceptionClass($exceptionMessage);
                }
                return self::$payload;
            }
        };
        $jwt::$payload = $payload;
        $jwt::$expectedException = $expectedException;

        $jwtClient = new FirebaseJwtClient(
            $jwt,
            $this->prophesize(JWK::class)->reveal()
        );

        if ($expectedException) {
            $this->expectException($expectedException['class']);
            $this->expectExceptionMessage($expectedException['message']);
        }

        $token = 'test.to.ken';
        $keys = [];
        $allowedAlgs = [];
        $response = $jwtClient->decode($token, $keys, $allowedAlgs);

        // This is only called when exceptions are not thrown
        $this->assertEquals($payload, $res);
    }

    public function provideDecode()
    {
        $payload =  [
            'iat' => time(),
            'exp' => time() + 30,
            'name' => 'foo',
            'iss' => GoogleAuth::OIDC_ISSUERS[0],
        ];
        return [
            [
                'payload' => $payload,
                'expectedException' => [
                    'class' => ExpiredException::class,
                    'message' => 'expired!'
                ]
            ],
            [
                'payload' => $payload,
                'expectedException' => [
                    'class' => SignatureInvalidException::class,
                    'message' => 'invalid signature!'
                ]
            ],
            [
                'payload' => $payload,
                'expectedException' => [
                    'class' => UnexpectedValueException::class,
                    'message' => 'invalid token!'
                ]
            ],
            [
                'payload' => $payload,
                'expectedException' => [
                    'class' => BeforeValidException::class,
                    'message' => 'ineligible cbf!'
                ]
            ],
        ];
    }

    public function testDecodeFailsIfTokenIsInvalid()
    {
        $this->expectException('UnexpectedValueException');

        $not_a_jwt = 'not a jwt';
        $jwtClient = new FirebaseJwtClient(new JWT, new JWK);
        $jwtClient->decode($not_a_jwt, ['keys' => []], ['algs']);
    }

    public function testEncodeDecode()
    {
        $publicKey = file_get_contents(__DIR__ . '/../fixtures/public.pem');
        $privateKey = file_get_contents(__DIR__ . '/../fixtures/private.pem');

        $now = time();
        $jwtPayload = [
            'aud' => 'myaccount.on.host.issuer.com',
            'iss' => 'an.issuer.com',
            'exp' => $now + 65, // arbitrary
            'iat' => $now,
        ];
        $jwtClient = new FirebaseJwtClient(new JWT, new JWK);
        $jwt = $jwtClient->encode($jwtPayload, $privateKey, 'RS256', 'kid');

        $decoded = $jwtClient->decode($jwt, ['kid' => $publicKey], ['RS256']);
        $this->assertEquals($jwtPayload['aud'], $decoded['aud']);
    }
}
