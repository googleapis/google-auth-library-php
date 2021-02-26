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

use Google\Auth\SignBlob\ServiceAccountApiSignBlobTrait;
use Google\Http\ClientInterface;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;

/**
 * @group iam
 *
 * @internal
 * @coversNothing
 */
class ServiceAccountApiSignBlobTraitTest extends TestCase
{
    /**
     * @dataProvider delegates
     */
    public function testSignBlob(array $delegates = [])
    {
        $expectedEmail = 'test@test.com';
        $expectedAccessToken = 'token';
        $expectedString = 'toSign';

        $expectedServiceAccount = sprintf(
            'projects/-/serviceAccounts/%s',
            $expectedEmail
        );

        $expectedUri = sprintf(
            'https://iamcredentials.googleapis.com/v1/%s:signBlob?alt=json',
            $expectedServiceAccount
        );

        $expectedResponse = 'signedString';

        if ($delegates) {
            $expectedDelegates = $delegates;
            foreach ($expectedDelegates as &$delegate) {
                $delegate = sprintf('projects/-/serviceAccounts/%s', $delegate);
            }
        } else {
            $expectedDelegates[] = $expectedServiceAccount;
        }

        $httpClient = httpClientFromCallable(function (Psr7\Request $request) use (
            $expectedAccessToken,
            $expectedString,
            $expectedUri,
            $expectedResponse,
            $expectedDelegates
        ) {
            $this->assertEquals($expectedUri, (string) $request->getUri());
            $this->assertEquals('Bearer ' . $expectedAccessToken, $request->getHeaderLine('Authorization'));
            $this->assertEquals([
                'delegates' => $expectedDelegates,
                'payload' => base64_encode($expectedString),
            ], json_decode((string) $request->getBody(), true));

            return new Psr7\Response(200, [], Utils::streamFor(json_encode([
                'signedBlob' => $expectedResponse
            ])));
        });

        $trait = new ServiceAccountApiSignBlobTraitImpl($httpClient);
        $res = $trait->signBlob(
            $expectedString,
            $expectedEmail,
            $expectedAccessToken,
            $delegates
        );

        $this->assertEquals($expectedResponse, $res);
    }

    public function delegates()
    {
        return [
            [],
            [['foo@bar.com']],
            [
                [
                    'foo@bar.com',
                    'bar@bar.com',
                ],
            ],
        ];
    }
}

class ServiceAccountApiSignBlobTraitImpl
{
    use ServiceAccountApiSignBlobTrait;

    private $httpClient;

    public function __construct(ClientInterface $httpClient)
    {
        $this->httpClient = $httpClient;
    }

    public function signBlob(
        $stringToSign,
        $email,
        $accessToken,
        $delegates
    ) {
        return $this->signBlobWithServiceAccountApi(
            $stringToSign,
            $email,
            $accessToken,
            $this->httpClient,
            $delegates
        );
    }
}
