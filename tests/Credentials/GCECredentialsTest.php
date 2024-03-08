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

use Exception;
use Google\Auth\Credentials\GCECredentials;
use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\Tests\BaseTest;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;

/**
 * @group credentials
 * @group credentials-gce
 */
class GCECredentialsTest extends BaseTest
{
    use ProphecyTrait;

    public function testOnGceMetadataFlavorHeader()
    {
        $hasHeader = false;
        $dummyHandler = function ($request) use (&$hasHeader) {
            $hasHeader = $request->getHeaderLine(GCECredentials::FLAVOR_HEADER) === 'Google';

            return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
        };

        $onGce = GCECredentials::onGce($dummyHandler);
        $this->assertTrue($hasHeader);
        $this->assertTrue($onGce);
    }

    public function testOnGceMetricsHeader()
    {
        $handerInvoked = false;
        $dummyHandler = function ($request) use (&$handerInvoked) {
            $header = $request->getHeaderLine('x-goog-api-client');
            $handerInvoked = true;
            $this->assertStringMatchesFormat(
                'gl-php/%s auth/%s auth-request-type/mds',
                $header
            );

            return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
        };

        GCECredentials::onGce($dummyHandler);
        $this->assertTrue($handerInvoked);
    }

    public function testOnGCEIsFalseOnClientErrorStatus()
    {
        // simulate retry attempts by returning multiple 400s
        $httpHandler = getHandler([
            new Response(400),
            new Response(400),
            new Response(400)
        ]);
        $this->assertFalse(GCECredentials::onGCE($httpHandler));
    }

    public function testOnGCEIsFalseOnServerErrorStatus()
    {
        // simulate retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            new Response(500),
            new Response(500),
            new Response(500)
        ]);
        $this->assertFalse(GCECredentials::onGCE($httpHandler));
    }

    public function testCheckProductNameFile()
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'gce-test-product-name');

        $method = (new \ReflectionClass(GCECredentials::class))
            ->getMethod('detectResidencyLinux');
        $method->setAccessible(true);

        $this->assertFalse($method->invoke(null, '/nonexistant/file'));

        file_put_contents($tmpFile, 'Google');
        $this->assertTrue($method->invoke(null, $tmpFile));

        file_put_contents($tmpFile, 'Not Google');
        $this->assertFalse($method->invoke(null, $tmpFile));
    }

    public function testOnGceWithResidency()
    {
        if (!GCECredentials::onGCE()) {
            $this->markTestSkipped('This test only works while running on GCE');
        }

        // If calling metadata server fails, this will check the residency file.
        $httpHandler = function () {
            // Mock an exception, such as a ping timeout
            throw $this->prophesize(ClientException::class)->reveal();
        };

        $this->assertTrue(GCECredentials::onGCE($httpHandler));
    }

    public function testOnGCEIsFalseOnOkStatusWithoutExpectedHeader()
    {
        $httpHandler = getHandler([
            new Response(200),
        ]);
        $this->assertFalse(GCECredentials::onGCE($httpHandler));
    }

    public function testOnGCEIsOkIfGoogleIsTheFlavor()
    {
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
        ]);
        $this->assertTrue(GCECredentials::onGCE($httpHandler));
    }

    public function testOnAppEngineFlexIsFalseByDefault()
    {
        $this->assertFalse(GCECredentials::onAppEngineFlexible());
    }

    public function testOnAppEngineFlexIsTrueWhenGaeInstanceHasAefPrefix()
    {
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $this->assertTrue(GCECredentials::onAppEngineFlexible());
        putenv('GAE_INSTANCE');
    }

    public function testGetCacheKeyShouldNotBeEmpty()
    {
        $g = new GCECredentials();
        $this->assertNotEmpty($g->getCacheKey());
    }

    public function testFetchAuthTokenShouldBeEmptyIfNotOnGCE()
    {
        // simulate retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            new Response(500),
            new Response(500),
            new Response(500)
        ]);
        $g = new GCECredentials();
        $this->assertEquals([], $g->fetchAuthToken($httpHandler));
    }

    public function testFetchAuthTokenShouldFailIfResponseIsNotJson()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid JSON response');

        $notJson = '{"foo": , this is cannot be passed as json" "bar"}';
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            new Response(200, [], $notJson),
        ]);
        $g = new GCECredentials();
        $g->fetchAuthToken($httpHandler);
    }

    public function testFetchAuthTokenShouldReturnTokenInfo()
    {
        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            new Response(200, [], Utils::streamFor($jsonTokens)),
        ]);
        $g = new GCECredentials();
        $receivedToken = $g->fetchAuthToken($httpHandler);
        $this->assertEquals(
            $wantedTokens['access_token'],
            $receivedToken['access_token']
        );
        $this->assertEquals(time() + 57, $receivedToken['expires_at']);
        $this->assertEquals(time() + 57, $g->getLastReceivedToken()['expires_at']);
    }

    public function testFetchAuthTokenShouldBeIdTokenWhenTargetAudienceIsSet()
    {
        $expectedToken = ['id_token' => 'idtoken12345'];
        $timesCalled = 0;
        $httpHandler = function ($request) use (&$timesCalled, $expectedToken) {
            $timesCalled++;
            if ($timesCalled == 1) {
                return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
            }
            $this->assertEquals(
                '/computeMetadata/' . GCECredentials::ID_TOKEN_URI_PATH,
                $request->getUri()->getPath()
            );
            $this->assertEquals(
                'audience=a+target+audience',
                $request->getUri()->getQuery()
            );
            return new Psr7\Response(200, [], Utils::streamFor($expectedToken['id_token']));
        };
        $g = new GCECredentials(null, null, 'a+target+audience');
        $this->assertEquals($expectedToken, $g->fetchAuthToken($httpHandler));
        $this->assertEquals(2, $timesCalled);
    }

    public function testSettingBothScopeAndTargetAudienceThrowsException()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Scope and targetAudience cannot both be supplied');

        $g = new GCECredentials(null, 'a-scope', 'a+target+audience');
    }

    /**
     * @dataProvider scopes
     */
    public function testFetchAuthTokenCustomScope($scope, $expected)
    {
        $uri = null;
        $client = $this->prophesize('GuzzleHttp\ClientInterface');
        $client->send(Argument::any(), Argument::any())
            ->will(function () use (&$uri) {
                $this->send(Argument::any(), Argument::any())->will(function ($args) use (&$uri) {
                    $uri = $args[0]->getUri();

                    return new Response(200, [], Utils::streamFor('{"expires_in": 0}'));
                });

                return new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
            });

        HttpClientCache::setHttpClient($client->reveal());

        $g = new GCECredentials(null, $scope);
        $g->fetchAuthToken();
        parse_str($uri->getQuery(), $query);

        $this->assertArrayHasKey('scopes', $query);
        $this->assertEquals($expected, $query['scopes']);
    }

    public function scopes()
    {
        return [
            ['foobar', 'foobar'],
            [['foobar'], 'foobar'],
            ['hello world', 'hello,world'],
            [['hello', 'world'], 'hello,world']
        ];
    }

    public function testGetLastReceivedTokenIsNullByDefault()
    {
        $creds = new GCECredentials();
        $this->assertNull($creds->getLastReceivedToken());
    }

    public function testGetLastReceivedTokenShouldWorkWithIdToken()
    {
        $idToken = '123asdfghjkl';
        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            new Response(200, [], Utils::streamFor($idToken)),
        ]);
        $g = new GCECredentials(null, null, 'https://example.test.com');
        $g->fetchAuthToken($httpHandler);
        $this->assertEquals(
            $idToken,
            $g->getLastReceivedToken()['id_token']
        );
    }

    public function testGetClientName()
    {
        $expected = 'foobar';

        $httpHandler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            new Response(200, [], Utils::streamFor($expected)),
            new Response(200, [], Utils::streamFor('notexpected'))
        ]);

        $creds = new GCECredentials();
        $this->assertEquals($expected, $creds->getClientName($httpHandler));

        // call again to test cached value
        $this->assertEquals($expected, $creds->getClientName($httpHandler));
    }

    public function testGetClientNameShouldBeEmptyIfNotOnGCE()
    {
        // simulate retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            new Response(500),
            new Response(500),
            new Response(500)
        ]);

        $creds = new GCECredentials();
        $this->assertEquals('', $creds->getClientName($httpHandler));
    }

    public function testSignBlob()
    {
        $expectedEmail = 'test@test.com';
        $expectedAccessToken = 'token';
        $stringToSign = 'inputString';
        $resultString = 'foobar';
        $token = [
            'access_token' => $expectedAccessToken,
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];

        $iam = $this->prophesize('Google\Auth\Iam');
        $iam->signBlob($expectedEmail, $expectedAccessToken, $stringToSign)
            ->shouldBeCalled()
            ->willReturn($resultString);

        $client = $this->prophesize('GuzzleHttp\ClientInterface');
        $client->send(Argument::any(), Argument::any())
            ->willReturn(
                new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
                new Response(200, [], Utils::streamFor($expectedEmail)),
                new Response(200, [], Utils::streamFor(json_encode($token)))
            );

        HttpClientCache::setHttpClient($client->reveal());

        $creds = new GCECredentials($iam->reveal());
        $signature = $creds->signBlob($stringToSign);
    }

    public function testSignBlobWithLastReceivedAccessToken()
    {
        $expectedEmail = 'test@test.com';
        $expectedAccessToken = 'token';
        $notExpectedAccessToken = 'othertoken';
        $stringToSign = 'inputString';
        $resultString = 'foobar';
        $token1 = [
            'access_token' => $expectedAccessToken,
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $token2 = [
            'access_token' => $notExpectedAccessToken,
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];

        $iam = $this->prophesize('Google\Auth\Iam');
        $iam->signBlob($expectedEmail, $expectedAccessToken, $stringToSign)
            ->shouldBeCalled()
            ->willReturn($resultString);

        $client = $this->prophesize('GuzzleHttp\ClientInterface');
        $client->send(Argument::any(), Argument::any())
            ->willReturn(
                new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
                new Response(200, [], Utils::streamFor(json_encode($token1))),
                new Response(200, [], Utils::streamFor($expectedEmail)),
                new Response(200, [], Utils::streamFor(json_encode($token2)))
            );

        HttpClientCache::setHttpClient($client->reveal());

        $creds = new GCECredentials($iam->reveal());
        // cache a token
        $creds->fetchAuthToken();

        $signature = $creds->signBlob($stringToSign);
    }

    public function testSignBlobWithUniverseDomain()
    {
        $token = [
            'access_token' => 'token',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $signedBlob = ['signedBlob' => 'abc123'];
        $client = $this->prophesize('GuzzleHttp\ClientInterface');
        $client->send(Argument::any(), Argument::any())
            ->willReturn(
                new Response(200, [], Utils::streamFor('test@test.com')),
                new Response(200, [], Utils::streamFor(json_encode($token)))
            );
        $client->send(
            Argument::that(
                fn (Request $request) => $request->getUri()->getHost() === 'iamcredentials.example-universe.com'
            ),
            Argument::any()
        )
            ->shouldBeCalledOnce()
            ->willReturn(new Response(200, [], Utils::streamFor(json_encode($signedBlob))));

        HttpClientCache::setHttpClient($client->reveal());

        $creds = new GCECredentials(
            null,
            null,
            null,
            null,
            null,
            'example-universe.com'
        );
        $creds->setIsOnGce(true);
        $signature = $creds->signBlob('inputString');
        $this->assertEquals('abc123', $signature);
    }

    public function testGetProjectId()
    {
        $expected = 'foobar';

        $client = $this->prophesize('GuzzleHttp\ClientInterface');
        $client->send(Argument::any(), Argument::any())
            ->willReturn(
                new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
                new Response(200, [], Utils::streamFor($expected)),
                new Response(200, [], Utils::streamFor('notexpected'))
            );

        HttpClientCache::setHttpClient($client->reveal());

        $creds = new GCECredentials();
        $this->assertEquals($expected, $creds->getProjectId());

        // call again to test cached value
        $this->assertEquals($expected, $creds->getProjectId());
    }

    public function testGetProjectIdShouldBeEmptyIfNotOnGCE()
    {
        // simulate retry attempts by returning multiple 500s
        $client = $this->prophesize('GuzzleHttp\ClientInterface');
        $client->send(Argument::any(), Argument::any())
            ->willReturn(
                new Response(500),
                new Response(500),
                new Response(500)
            );

        HttpClientCache::setHttpClient($client->reveal());

        $creds = new GCECredentials();
        $this->assertNull($creds->getProjectId());
    }

    public function testGetTokenUriWithServiceAccountIdentity()
    {
        $tokenUri = GCECredentials::getTokenUri('foo');
        $this->assertEquals(
            'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/foo/token',
            $tokenUri
        );
    }

    public function testSetIsOnGceToFalseReturnsEmptyCreds()
    {
        $creds = new GCECredentials();
        $creds->setIsOnGce(false);
        $this->assertEquals([], $creds->fetchAuthToken());
    }

    public function testSetIsOnGceToTrueWhenNotOnGceThrowsException()
    {
        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('408 Request Time-out');

        $httpHandler = getHandler([new Response(408)]);
        $creds = new GCECredentials();
        $creds->setIsOnGce(true);
        $creds->fetchAuthToken($httpHandler);
    }

    public function testGetAccessTokenWithServiceAccountIdentity()
    {
        $expected = [
            'access_token' => 'token12345',
            'expires_in' => 123,
        ];
        $timesCalled = 0;
        $httpHandler = function ($request) use (&$timesCalled, $expected) {
            $timesCalled++;
            if ($timesCalled == 1) {
                return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
            }
            $this->assertEquals(
                '/computeMetadata/v1/instance/service-accounts/foo/token',
                $request->getUri()->getPath()
            );
            $this->assertEquals('', $request->getUri()->getQuery());
            return new Psr7\Response(200, [], Utils::streamFor(json_encode($expected)));
        };

        $g = new GCECredentials(null, null, null, null, 'foo');
        $this->assertEquals(
            $expected['access_token'],
            $g->fetchAuthToken($httpHandler)['access_token']
        );
    }

    public function testGetIdTokenWithServiceAccountIdentity()
    {
        $expected = 'idtoken12345';
        $timesCalled = 0;
        $httpHandler = function ($request) use (&$timesCalled, $expected) {
            $timesCalled++;
            if ($timesCalled == 1) {
                return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
            }
            $this->assertEquals(
                '/computeMetadata/v1/instance/service-accounts/foo/identity',
                $request->getUri()->getPath()
            );
            $this->assertEquals(
                'audience=a+target+audience',
                $request->getUri()->getQuery()
            );
            return new Psr7\Response(200, [], Utils::streamFor($expected));
        };
        $g = new GCECredentials(null, null, 'a+target+audience', null, 'foo');
        $this->assertEquals(
            ['id_token' => $expected],
            $g->fetchAuthToken($httpHandler)
        );
    }

    public function testGetClientNameUriWithServiceAccountIdentity()
    {
        $clientNameUri = GCECredentials::getClientNameUri('foo');
        $this->assertEquals(
            'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/foo/email',
            $clientNameUri
        );
    }

    public function testGetClientNameWithServiceAccountIdentity()
    {
        $expected = 'expected';
        $timesCalled = 0;
        $httpHandler = function ($request) use (&$timesCalled, $expected) {
            $timesCalled++;
            if ($timesCalled == 1) {
                return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
            }
            $this->assertEquals(
                '/computeMetadata/v1/instance/service-accounts/foo/email',
                $request->getUri()->getPath()
            );
            $this->assertEquals('', $request->getUri()->getQuery());
            return new Psr7\Response(200, [], Utils::streamFor($expected));
        };

        $creds = new GCECredentials(null, null, null, null, 'foo');
        $this->assertEquals($expected, $creds->getClientName($httpHandler));
    }

    public function testGetUniverseDomain()
    {
        $creds = new GCECredentials();
        $creds->setIsOnGce(true);

        // Pretend we are on GCE and mock the http handler.
        $expected = 'example-universe.com';
        $timesCalled = 0;
        $httpHandler = function ($request) use (&$timesCalled, $expected) {
            $timesCalled++;
            $this->assertEquals(
                '/computeMetadata/v1/universe/universe_domain',
                $request->getUri()->getPath()
            );
            $this->assertEquals(1, $timesCalled, 'should only be called once');
            return new Psr7\Response(200, [], Utils::streamFor($expected));
        };

        // Assert correct universe domain.
        $this->assertEquals($expected, $creds->getUniverseDomain($httpHandler));

        // Assert the result is cached for subsequent calls.
        $this->assertEquals($expected, $creds->getUniverseDomain($httpHandler));
    }

    public function testGetUniverseDomainEmptyStringReturnsDefault()
    {
        $creds = new GCECredentials();
        $creds->setIsOnGce(true);

        // Pretend we are on GCE and mock the MDS returning an empty string for the universe domain.
        $httpHandler = function ($request) {
            $this->assertEquals(
                '/computeMetadata/v1/universe/universe_domain',
                $request->getUri()->getPath()
            );
            return new Psr7\Response(200, [], Utils::streamFor(''));
        };

        // Assert the default universe domain is returned instead of the empty string.
        $this->assertEquals(
            GCECredentials::DEFAULT_UNIVERSE_DOMAIN,
            $creds->getUniverseDomain($httpHandler)
        );
    }

    public function testExplicitUniverseDomain()
    {
        $expected = 'example-universe.com';
        $creds = new GCECredentials(null, null, null, null, null, $expected);
        $this->assertEquals($expected, $creds->getUniverseDomain());
    }
}
