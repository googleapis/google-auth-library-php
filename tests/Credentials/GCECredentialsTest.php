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

use Google\Auth\Credentials\GCECredentials;
use Google\Auth\HttpHandler\HttpClientCache;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;

/**
 * @group credentials
 * @group credentials-gce
 */
class GCECredentialsTest extends TestCase
{
    public function testOnGCEIsFalseOnClientErrorStatus()
    {
        // simulate retry attempts by returning multiple 400s
        $httpHandler = getHandler([
            buildResponse(400),
            buildResponse(400),
            buildResponse(400)
        ]);
        $this->assertFalse(GCECredentials::onGCE($httpHandler));
    }

    public function testOnGCEIsFalseOnServerErrorStatus()
    {
        // simulate retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            buildResponse(500),
            buildResponse(500),
            buildResponse(500)
        ]);
        $this->assertFalse(GCECredentials::onGCE($httpHandler));
    }

    public function testOnGCEIsFalseOnOkStatusWithoutExpectedHeader()
    {
        $httpHandler = getHandler([
            buildResponse(200),
        ]);
        $this->assertFalse(GCECredentials::onGCE($httpHandler));
    }

    public function testOnGCEIsOkIfGoogleIsTheFlavor()
    {
        $httpHandler = getHandler([
            buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
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
            buildResponse(500),
            buildResponse(500),
            buildResponse(500)
        ]);
        $g = new GCECredentials();
        $this->assertEquals(array(), $g->fetchAuthToken($httpHandler));
    }

    /**
     * @expectedException Exception
     * @expectedExceptionMessage Invalid JSON response
     */
    public function testFetchAuthTokenShouldFailIfResponseIsNotJson()
    {
        $notJson = '{"foo": , this is cannot be passed as json" "bar"}';
        $httpHandler = getHandler([
            buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], $notJson),
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
            buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);
        $g = new GCECredentials();
        $this->assertEquals($wantedTokens, $g->fetchAuthToken($httpHandler));
        $this->assertEquals(time() + 57, $g->getLastReceivedToken()['expires_at']);
    }

    public function testGetLastReceivedTokenIsNullByDefault()
    {
        $creds = new GCECredentials;
        $this->assertNull($creds->getLastReceivedToken());
    }

    public function testGetClientName()
    {
        $expected = 'foobar';

        $httpHandler = getHandler([
            buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($expected)),
            buildResponse(200, [], Psr7\stream_for('notexpected'))
        ]);

        $creds = new GCECredentials;
        $this->assertEquals($expected, $creds->getClientName($httpHandler));

        // call again to test cached value
        $this->assertEquals($expected, $creds->getClientName($httpHandler));
    }

    public function testGetClientNameShouldBeEmptyIfNotOnGCE()
    {
        // simulate retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            buildResponse(500),
            buildResponse(500),
            buildResponse(500)
        ]);

        $creds = new GCECredentials;
        $this->assertEquals('', $creds->getClientName($httpHandler));
    }

    public function testSignBlob()
    {
        $guzzleVersion = ClientInterface::VERSION;
        if ($guzzleVersion[0] === '5') {
            $this->markTestSkipped('Only compatible with guzzle 6+');
        }

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
                buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
                buildResponse(200, [], Psr7\stream_for($expectedEmail)),
                buildResponse(200, [], Psr7\stream_for(json_encode($token)))
            );

        HttpClientCache::setHttpClient($client->reveal());

        $creds = new GCECredentials($iam->reveal());
        $signature = $creds->signBlob($stringToSign);
    }

    public function testSignBlobWithLastReceivedAccessToken()
    {
        $guzzleVersion = ClientInterface::VERSION;
        if ($guzzleVersion[0] === '5') {
            $this->markTestSkipped('Only compatible with guzzle 6+');
        }

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
                buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
                buildResponse(200, [], Psr7\stream_for(json_encode($token1))),
                buildResponse(200, [], Psr7\stream_for($expectedEmail)),
                buildResponse(200, [], Psr7\stream_for(json_encode($token2)))
            );

        HttpClientCache::setHttpClient($client->reveal());

        $creds = new GCECredentials($iam->reveal());
        // cache a token
        $creds->fetchAuthToken();

        $signature = $creds->signBlob($stringToSign);
    }
}
