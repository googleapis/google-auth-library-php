<?php
/**
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

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\SignatureInvalidException;
use Google\Auth\AccessToken;
use GuzzleHttp\Psr7\Response;
use phpseclib\Crypt\RSA;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Http\Message\RequestInterface;
use SimpleJWT\JWT as SimpleJWT;

/**
 * @group access-token
 */
class AccessTokenTest extends TestCase
{
    private $cache;
    private $payload;

    private $token;
    private $publicKey;
    private $allowedAlgs;

    public function setUp()
    {
        $this->cache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $this->jwt = $this->prophesize('Firebase\JWT\JWT');
        $this->token = 'foobar';
        $this->publicKey = 'barfoo';
        $this->allowedAlgs = ['RS256'];

        $this->payload = [
            'iat' => time(),
            'exp' => time() + 30,
            'name' => 'foo',
            'iss' => AccessToken::OAUTH2_ISSUER_HTTPS
        ];
    }

    /**
     * @dataProvider verifyCalls
     */
    public function testVerify(
        $payload,
        $expected,
        $audience = null,
        callable $verifyCallback = null,
        $certsLocation = null
    ) {
        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()->willReturn([
            'keys' => [
                [
                    'kid' => 'ddddffdfd',
                    'e' => 'AQAB',
                    'kty' => 'RSA',
                    'alg' => 'RS256',
                    'n' => $this->publicKey,
                    'use' => 'sig'
                ]
            ]
        ]);

        $cacheKey = 'google_auth_certs_cache|' .
            ($certsLocation ? sha1($certsLocation) : 'federated_signon_certs_v3');
        $this->cache->getItem($cacheKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $token = new AccessTokenStub(
            null,
            $this->cache->reveal()
        );

        $token->mocks['decode'] = function ($token, $publicKey, $allowedAlgs) use ($payload, $verifyCallback) {
            $this->assertEquals($this->token, $token);
            $this->assertEquals($this->allowedAlgs, $allowedAlgs);

            if ($verifyCallback) {
                $verifyCallback($token, $publicKey, $allowedAlgs);
            }

            return (object) $payload;
        };

        $res = $token->verify($this->token, [
            'audience' => $audience,
            'certsLocation' => $certsLocation,
        ]);
        $this->assertEquals($expected, $res);
    }

    public function verifyCalls()
    {
        $this->setUp();

        return [
            [
                $this->payload,
                $this->payload,
            ], [
                $this->payload + [
                    'aud' => 'foo'
                ],
                $this->payload + [
                    'aud' => 'foo'
                ],
                'foo'
            ], [
                $this->payload + [
                    'aud' => 'foo'
                ],
                false,
                'bar'
            ], [
                [
                    'iss' => 'invalid'
                ] + $this->payload,
                false
            ], [
                $this->payload,
                false,
                null,
                function () {
                    if (class_exists('Firebase\JWT\ExpiredException')) {
                        throw new ExpiredException('expired!');
                    } else {
                        throw new \ExpiredException('expired');
                    }
                }
            ], [
                $this->payload,
                false,
                null,
                function () {
                    if (class_exists('Firebase\JWT\SignatureInvalidException')) {
                        throw new SignatureInvalidException('invalid!');
                    } else {
                        throw new \SignatureInvalidException('invalid');
                    }
                }
            ], [
                $this->payload,
                false,
                null,
                function () {
                    throw new \DomainException('expired!');
                }
            ],
            [
                $this->payload,
                $this->payload,
                null,
                null,
                AccessToken::IAP_CERT_URL
            ],
        ];
    }

    public function testEsVerifyEndToEnd()
    {
        if (!$jwt = getenv('IAP_IDENTITY_TOKEN')) {
            $this->markTestSkipped('Set the IAP_IDENTITY_TOKEN env var');
        }

        $token = new AccessTokenStub();
        $token->mocks['simpleJwtDecode'] = function ($token, $publicKey, $allowedAlgs) {
            // Skip expired validation
            return SimpleJWT::decode(
                $token,
                $publicKey,
                $allowedAlgs,
                null,
                ['exp']
            );
        };

        // Use Iap Cert URL
        $payload = $token->verify($jwt, [
            'certsLocation' => AccessToken::IAP_CERT_URL,
        ]);

        $this->assertNotFalse($payload);
        $this->assertArrayHasKey('iss', $payload);
        $this->assertEquals('https://cloud.google.com/iap', $payload['iss']);
    }

    public function testGetCertsForIap()
    {
        $token = new AccessToken();
        $reflector = new \ReflectionObject($token);
        $cacheKeyMethod = $reflector->getMethod('getCacheKeyFromCertLocation');
        $cacheKeyMethod->setAccessible(true);
        $getCertsMethod = $reflector->getMethod('getCerts');
        $getCertsMethod->setAccessible(true);
        $cacheKey = $cacheKeyMethod->invoke($token, AccessToken::IAP_CERT_URL);
        $certs = $getCertsMethod->invoke(
            $token,
            AccessToken::IAP_CERT_URL,
            $cacheKey
        );
        $this->assertTrue(is_array($certs));
        $this->assertEquals(5, count($certs));
    }

    public function testRetrieveCertsFromLocationLocalFile()
    {
        $certsLocation = __DIR__ . '/fixtures/federated-certs.json';
        $certsData = json_decode(file_get_contents($certsLocation), true);

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);
        $item->set($certsData)
            ->shouldBeCalledTimes(1);
        $item->expiresAt(Argument::type('\DateTime'))
            ->shouldBeCalledTimes(1);

        $this->cache->getItem('google_auth_certs_cache|' . sha1($certsLocation))
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $this->cache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalledTimes(1);

        $token = new AccessTokenStub(
            null,
            $this->cache->reveal()
        );

        $token->mocks['decode'] = function ($token, $publicKey, $allowedAlgs) {
            $this->assertEquals($this->token, $token);
            $this->assertEquals($this->allowedAlgs, $allowedAlgs);

            return (object) $this->payload;
        };

        $token->verify($this->token, [
            'certsLocation' => $certsLocation
        ]);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage Failed to retrieve verification certificates from path
     */
    public function testRetrieveCertsFromLocationLocalFileInvalidFilePath()
    {
        $certsLocation = __DIR__ . '/fixtures/federated-certs-does-not-exist.json';

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->cache->getItem('google_auth_certs_cache|' . sha1($certsLocation))
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $token = new AccessTokenStub(
            null,
            $this->cache->reveal()
        );

        $token->verify($this->token, [
            'certsLocation' => $certsLocation
        ]);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage federated sign-on certs expects "keys" to be set
     */
    public function testRetrieveCertsInvalidData()
    {
        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn('{}');

        $this->cache->getItem('google_auth_certs_cache|federated_signon_certs_v3')
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $token = new AccessTokenStub(
            null,
            $this->cache->reveal()
        );

        $token->verify($this->token);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage federated sign-on certs expects "keys" to be set
     */
    public function testRetrieveCertsFromLocationLocalFileInvalidFileData()
    {
        $temp = tmpfile();
        fwrite($temp, '{}');
        $certsLocation = stream_get_meta_data($temp)['uri'];

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->cache->getItem('google_auth_certs_cache|' . sha1($certsLocation))
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $token = new AccessTokenStub(
            null,
            $this->cache->reveal()
        );

        $token->verify($this->token, [
            'certsLocation' => $certsLocation
        ]);
    }

    public function testRetrieveCertsFromLocationRemote()
    {
        $certsLocation = __DIR__ . '/fixtures/federated-certs.json';
        $certsJson = file_get_contents($certsLocation);
        $certsData = json_decode($certsJson, true);

        $httpHandler = function (RequestInterface $request) use ($certsJson) {
            $this->assertEquals(AccessToken::FEDERATED_SIGNON_CERT_URL, (string) $request->getUri());
            $this->assertEquals('GET', $request->getMethod());

            return new Response(200, [], $certsJson);
        };

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);
        $item->set($certsData)
            ->shouldBeCalledTimes(1);
        $item->expiresAt(Argument::type('\DateTime'))
            ->shouldBeCalledTimes(1);

        $this->cache->getItem('google_auth_certs_cache|federated_signon_certs_v3')
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $this->cache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalledTimes(1);

        $token = new AccessTokenStub(
            $httpHandler,
            $this->cache->reveal()
        );

        $token->mocks['decode'] = function ($token, $publicKey, $allowedAlgs) {
            $this->assertEquals($this->token, $token);
            $this->assertEquals($this->allowedAlgs, $allowedAlgs);

            return (object) $this->payload;
        };

        $token->verify($this->token);
    }

    /**
     * @expectedException RuntimeException
     * @expectedExceptionMessage bad news guys
     */
    public function testRetrieveCertsFromLocationRemoteBadRequest()
    {
        $badBody = 'bad news guys';

        $httpHandler = function (RequestInterface $request) use ($badBody) {
            return new Response(500, [], $badBody);
        };

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->cache->getItem('google_auth_certs_cache|federated_signon_certs_v3')
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $token = new AccessTokenStub(
            $httpHandler,
            $this->cache->reveal()
        );

        $token->verify($this->token);
    }

    /**
     * @dataProvider revokeTokens
     */
    public function testRevoke($input, $expected)
    {
        $httpHandler = function (RequestInterface $request) use ($expected) {
            $this->assertEquals('no-store', $request->getHeaderLine('Cache-Control'));
            $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
            $this->assertEquals('POST', $request->getMethod());
            $this->assertEquals(AccessToken::OAUTH2_REVOKE_URI, (string) $request->getUri());
            $this->assertEquals('token=' . $expected, (string) $request->getBody());

            return new Response(200);
        };

        $token = new AccessToken($httpHandler);

        $this->assertTrue($token->revoke($input));
    }

    public function revokeTokens()
    {
        $this->setUp();

        return [
            [
                $this->token,
                $this->token
            ], [
                ['refresh_token' => $this->token, 'access_token' => 'other thing'],
                $this->token
            ], [
                ['access_token' => $this->token],
                $this->token
            ]
        ];
    }

    public function testRevokeFails()
    {
        $httpHandler = function (RequestInterface $request) {
            return new Response(500);
        };

        $token = new AccessToken($httpHandler);

        $this->assertFalse($token->revoke($this->token));
    }
}

//@codingStandardsIgnoreStart
class AccessTokenStub extends AccessToken
{
    public $mocks = [];

    protected function callJwtStatic($method, array $args = [])
    {
        return isset($this->mocks[$method])
            ? call_user_func_array($this->mocks[$method], $args)
            : parent::callJwtStatic($method, $args);
    }

    protected function callSimpleJwtDecode(array $args = [])
    {
        return isset($this->mocks['simpleJwtDecode'])
            ? call_user_func_array($this->mocks['simpleJwtDecode'], $args)
            : parent::callSimpleJwtDecode($args);
    }
}
//@codingStandardsIgnoreEnd
