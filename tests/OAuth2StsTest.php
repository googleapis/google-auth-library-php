<?php
/*
 * Copyright 2010 Google Inc.
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

use Google\Auth\ExternalAccountCredentialSourceInterface;
use Google\Auth\OAuth2;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;

class OAuth2StsTest extends TestCase
{
    use ProphecyTrait;

    private $publicKey;
    private $privateKey;
    private $stsMinimal = [
        'tokenCredentialUri' => 'https://tokens_r_us/test',
        'subjectTokenType' => 'urn:ietf:params:aws:token-type:aws4_request',
    ];

    public function testStsGrantType()
    {
        $credentialSource = $this->prophesize(ExternalAccountCredentialSourceInterface::class);
        $o = new OAuth2($this->stsMinimal + ['subjectTokenFetcher' => $credentialSource->reveal()]);
        $this->assertEquals(OAuth2::STS_URN, $o->getGrantType());
    }

    public function testStsCredentialsRequestMinimal()
    {
        $credentialSource = $this->prophesize(ExternalAccountCredentialSourceInterface::class);
        $credentialSource->fetchSubjectToken(null)
            ->shouldBeCalledOnce()
            ->willReturn('xyz');
        $o = new OAuth2($this->stsMinimal + ['subjectTokenFetcher' => $credentialSource->reveal()]);
        $request = $o->generateCredentialsRequest();
        $this->assertEquals('POST', $request->getMethod());
        $this->assertEquals($this->stsMinimal['tokenCredentialUri'], (string) $request->getUri());
        parse_str((string) $request->getBody(), $requestParams);
        $this->assertCount(4, $requestParams);
        $this->assertEquals(OAuth2::STS_URN, $requestParams['grant_type']);
        $this->assertEquals('xyz', $requestParams['subject_token']);
        $this->assertEquals($this->stsMinimal['subjectTokenType'], $requestParams['subject_token_type']);
    }

    public function testStsCredentialsRequestFull()
    {
        $credentialSource = $this->prophesize(ExternalAccountCredentialSourceInterface::class);
        $credentialSource->fetchSubjectToken(null)
            ->shouldBeCalledOnce()
            ->willReturn('xyz');
        $stsMinimal = $this->stsMinimal + [
            'subjectTokenFetcher' => $credentialSource->reveal(),
            'resource' => 'abc',
            'scope' => ['scope1', 'scope2'],
            'audience' => 'def',
            'actorToken' => '123',
            'actorTokenType' => 'urn:ietf:params:oauth:token-type:access_token',
        ];
        $o = new OAuth2($stsMinimal);
        $request = $o->generateCredentialsRequest();
        $this->assertEquals('POST', $request->getMethod());
        $this->assertEquals($this->stsMinimal['tokenCredentialUri'], (string) $request->getUri());
        parse_str((string) $request->getBody(), $requestParams);

        $this->assertCount(9, $requestParams);
        $this->assertEquals(OAuth2::STS_URN, $requestParams['grant_type']);
        $this->assertEquals('xyz', $requestParams['subject_token']);
        $this->assertEquals($stsMinimal['subjectTokenType'], $requestParams['subject_token_type']);
        $this->assertEquals($stsMinimal['resource'], $requestParams['resource']);
        $this->assertEquals('scope1 scope2', $requestParams['scope']);
        $this->assertEquals($stsMinimal['audience'], $requestParams['audience']);
        $this->assertEquals($stsMinimal['actorToken'], $requestParams['actor_token']);
        $this->assertEquals($stsMinimal['actorTokenType'], $requestParams['actor_token_type']);
    }
}
