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

namespace Google\Jwt\Client\Tests;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Google\Auth\GoogleAuth;
use Google\Jwt\Client\FirebaseClient;
use Google\Jwt\VerificationFailedException;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

/**
 * @internal
 * @covers \Google\Jwt\Client\FirebaseClient
 */
class FirebaseClientTest extends TestCase
{
    /**
     * @dataProvider provideDecode
     */
    public function testDecode(
        array $payload,
        array $expectedException = null,
        int $exceptionCode = null
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

        $jwtClient = new FirebaseClient(
            $jwt,
            $this->prophesize(JWK::class)->reveal()
        );

        if ($exceptionCode) {
            $this->expectException(VerificationFailedException::class);
            $this->expectExceptionMessage($expectedException['message']);
            $this->expectExceptionCode($exceptionCode);
        } elseif ($expectedException) {
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
        $payload = [
            'iat' => time(),
            'exp' => time() + 30,
            'name' => 'foo',
            'iss' => GoogleAuth::OIDC_ISSUERS[0],
        ];

        return [
            [
                'payload' => $payload,
                'exception' => [
                    'class' => ExpiredException::class,
                    'message' => 'expired!',
                ],
                'exceptionCode' => VerificationFailedException::EXPIRED,
            ],
            [
                'payload' => $payload,
                'exception' => [
                    'class' => SignatureInvalidException::class,
                    'message' => 'invalid signature!',
                ],
                'exceptionCode' => VerificationFailedException::SIGNATURE_INVALID,
            ],
            [
                'payload' => $payload,
                'exception' => [
                    'class' => UnexpectedValueException::class,
                    'message' => 'invalid token!',
                ],
            ],
            [
                'payload' => $payload,
                'exception' => [
                    'class' => BeforeValidException::class,
                    'message' => 'ineligible cbf!',
                ],
                'exceptionCode' => VerificationFailedException::BEFORE_VALID,
            ],
        ];
    }

    public function testDecodeFailsIfTokenIsInvalid()
    {
        $this->expectException('UnexpectedValueException');

        $not_a_jwt = 'not a jwt';
        $jwtClient = new FirebaseClient(new JWT(), new JWK());
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
        $jwtClient = new FirebaseClient(new JWT(), new JWK());
        $jwt = $jwtClient->encode($jwtPayload, $privateKey, 'RS256', 'kid');

        $decoded = $jwtClient->decode($jwt, ['kid' => $publicKey], ['RS256']);
        $this->assertEquals($jwtPayload['aud'], $decoded['aud']);
    }

    public function testGetExpirationWithoutVerification()
    {
        $jwtClient = new FirebaseClient(new JWT(), new JWK());
        $expectedExp = 12345;
        $jwt = implode('.', [
            'fake-header',
            base64_encode(json_encode(['exp' => $expectedExp])),
            'fake-sig',
        ]);
        $exp = $jwtClient->getExpirationWithoutVerification($jwt);
        $this->assertEquals($expectedExp, $exp);

        $expectedExpString = '12345';
        $jwt = implode('.', [
            'fake-header',
            base64_encode(json_encode(['exp' => $expectedExpString])),
            'fake-sig',
        ]);
        $exp = $jwtClient->getExpirationWithoutVerification($jwt);
        $this->assertEquals($expectedExpString, $exp);
    }

    public function testGetExpirationWithoutVerificationWithInvalidExp()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Expiration is not numeric');

        $jwtClient = new FirebaseClient(new JWT(), new JWK());
        $expectedExp = 'thisisnotanint';
        $jwt = implode('.', [
            'fake-header',
            base64_encode(json_encode(['exp' => $expectedExp])),
            'fake-sig',
        ]);

        $jwtClient->getExpirationWithoutVerification($jwt);
    }

    public function testGetExpirationWithoutVerificationWithWrongNumberOfSegments()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong number of segments');

        $jwtClient = new FirebaseClient(new JWT(), new JWK());
        $jwtClient->getExpirationWithoutVerification('thisisnota.jwt');
    }

    public function testVerificationWithExpired()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong number of segments');

        $jwtClient = new FirebaseClient(new JWT(), new JWK());
        $jwtClient->getExpirationWithoutVerification('thisisnota.jwt');
    }

    public function testExpiredToken()
    {
        $this->expectException(VerificationFailedException::class);
        $this->expectExceptionCode(VerificationFailedException::EXPIRED);

        $payload = [
            'message' => 'abc',
            'exp' => time() - 20,
        ]; // time in the past

        $jwtClient = new FirebaseClient(new JWT(), new JWK());

        $encoded = $jwtClient->encode($payload, 'my_key', 'HS256', 'key1');
        $jwtClient->decode($encoded, ['key1' => 'my_key'], ['HS256']);
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->expectException(VerificationFailedException::class);
        $this->expectExceptionCode(VerificationFailedException::BEFORE_VALID);

        $payload = [
            'message' => 'abc',
            'nbf' => time() + 20,
        ]; // time in the future

        $jwtClient = new FirebaseClient(new JWT(), new JWK());

        $encoded = $jwtClient->encode($payload, 'my_key', 'HS256', 'key1');
        $jwtClient->decode($encoded, ['key1' => 'my_key'], ['HS256']);
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->expectException(VerificationFailedException::class);
        $this->expectExceptionCode(VerificationFailedException::BEFORE_VALID);

        $payload = [
            'message' => 'abc',
            'iat' => time() + 20,
        ]; // time in the future

        $jwtClient = new FirebaseClient(new JWT(), new JWK());

        $encoded = $jwtClient->encode($payload, 'my_key', 'HS256', 'key1');
        $jwtClient->decode($encoded, ['key1' => 'my_key'], ['HS256']);
    }

    public function testSignatureInvalidToken()
    {
        $this->expectException(VerificationFailedException::class);
        $this->expectExceptionCode(VerificationFailedException::SIGNATURE_INVALID);

        $payload = [
            'message' => 'abc',
            'exp' => time() + 20,
        ]; // time in the future

        $jwtClient = new FirebaseClient(new JWT(), new JWK());

        $encoded = $jwtClient->encode($payload, 'my_key', 'HS256', 'key1');
        $jwtClient->decode($encoded, ['key1' => 'my_key2'], ['HS256']);
    }
}
