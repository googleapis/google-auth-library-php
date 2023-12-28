<?php
/*
 * Copyright 2023 Google Inc.
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
use Google\Auth\Credentials\ImpersonatedServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountJwtAccessCredentials;
use Google\Auth\Credentials\UserRefreshCredentials;
use Google\Auth\MetricsTrait;
use Google\Auth\UpdateMetadataInterface;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;

class MetricsTraitTest extends TestCase
{
    use ProphecyTrait;

    private $impl;

    private static $headerKey = 'x-goog-api-client';

    private $langAndVersion;

    private $jsonTokens;

    public function setUp(): void
    {
        $this->impl = new class() {
            use MetricsTrait {
                getVersion as public;
            }
        };
        $this->langAndVersion = sprintf(
            'gl-php/%s auth/%s',
            PHP_VERSION,
            $this->impl::getVersion()
        );
        $this->jsonTokens = json_encode(['access_token' => '1/abdef1234567890', 'expires_in' => '57']);
    }

    public function testGetVersion()
    {
        $actualVersion = $this->impl::getVersion();
        $this->assertStringMatchesFormat('%d.%d.%d', $actualVersion);
    }

    /**
     * @dataProvider tokenRequestType
     */
    public function testGCECredentials($scope, $targetAudience, $requestTypeHeaderValue)
    {
        $handlerCalled = false;
        $jsonTokens = $this->jsonTokens;
        $handler = getHandler([
            new Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            function ($request, $options) use (
                $jsonTokens,
                &$handlerCalled,
                $requestTypeHeaderValue
            ) {
                $handlerCalled = true;
                // This confirms that token endpoint requests have proper observability metric headers
                $this->assertStringContainsString(
                    sprintf('%s %s cred-type/mds', $this->langAndVersion, $requestTypeHeaderValue),
                    $request->getHeaderLine(self::$headerKey)
                );
                return new Response(200, [], Utils::streamFor($jsonTokens));
            }
        ]);

        $gceCred = new GCECredentials(null, $scope, $targetAudience);
        $this->assertUpdateMetadata($gceCred, $handler, 'mds', $handlerCalled);
    }

    /**
     * @dataProvider tokenRequestType
     */
    public function testServiceAccountCredentials($scope, $targetAudience, $requestTypeHeaderValue)
    {
        $keyFile = __DIR__ . '/fixtures3/service_account_credentials.json';
        $handlerCalled = false;
        $handler = $this->getCustomHandler('sa', $requestTypeHeaderValue, $handlerCalled);

        $sa = new ServiceAccountCredentials(
            $scope,
            $keyFile,
            null,
            $targetAudience
        );
        $this->assertUpdateMetadata($sa, $handler, 'sa', $handlerCalled);
    }

    /**
     * ServiceAccountJwtAccessCredentials creates the jwt token within library hence
     * they don't have any observability metrics header check for token endpoint requests.
     */
    public function testServiceAccountJwtAccessCredentials()
    {
        $keyFile = __DIR__ . '/fixtures3/service_account_credentials.json';
        $saJwt = new ServiceAccountJwtAccessCredentials($keyFile, 'exampleScope');
        $metadata = $saJwt->updateMetadata([], null, null);
        $this->assertArrayHasKey(self::$headerKey, $metadata);

        // This confirms that service usage requests have proper observability metric headers
        $this->assertStringContainsString(
            sprintf('%s cred-type/jwt', $this->langAndVersion),
            $metadata[self::$headerKey]
        );
    }

    /**
     * ImpersonatedServiceAccountCredentials haven't enabled identity token support hence
     * they don't have 'auth-request-type/it' observability metric header check.
    public function testImpersonatedServiceAccountCredentials()
    {
        $keyFile = __DIR__ . '/fixtures5/.config/gcloud/application_default_credentials.json';
        $handlerCalled = false;
        $handler = $this->getCustomHandler('imp', 'auth-request-type/at', $handlerCalled);

        $impersonatedCred = new ImpersonatedServiceAccountCredentials('exampleScope', $keyFile);
        $this->assertUpdateMetadata($impersonatedCred, $handler, 'imp', $handlerCalled);
    }

    /**
     * UserRefreshCredentials haven't enabled identity token support hence
     * they don't have 'auth-request-type/it' observability metric header check.
     */
    public function testUserRefreshCredentials()
    {
        $keyFile = __DIR__ . '/fixtures2/gcloud.json';
        $handlerCalled = false;
        $handler = $this->getCustomHandler('u', 'auth-request-type/at', $handlerCalled);

        $userRefreshCred = new UserRefreshCredentials('exampleScope', $keyFile);
        $this->assertUpdateMetadata($userRefreshCred, $handler, 'u', $handlerCalled);
    }

    /**
     * Invokes the 'updateMetadata' method of cred fetcher with empty metadata argument
     * and asserts for proper service api usage observability metrics header.
     */
    private function assertUpdateMetadata($cred, $handler, $credShortform, &$handlerCalled)
    {
        $metadata = $cred->updateMetadata([], null, $handler);
        $this->assertArrayHasKey(self::$headerKey, $metadata);

        // This confirms that service usage requests have proper observability metric headers
        $this->assertStringContainsString(
            sprintf('%s cred-type/%s', $this->langAndVersion, $credShortform),
            $metadata[self::$headerKey]
        );

        $this->assertTrue($handlerCalled);
    }

    /**
     * @param string $credShortform The short form of the credential type
     *        used in observability metric header value.
     * @param string $requestTypeHeaderValue Expected header value of the form
     *        'auth-request-type/<>'
     * @param bool $handlerCalled Reference to the handlerCalled flag asserted later
     *        in the test.
     * @return callable
     */
    private function getCustomHandler($credShortform, $requestTypeHeaderValue, &$handlerCalled)
    {
        $jsonTokens = $this->jsonTokens;
        return getHandler([
            function ($request, $options) use (
                $jsonTokens,
                &$handlerCalled,
                $requestTypeHeaderValue,
                $credShortform
            ) {
                $handlerCalled = true;
                // This confirms that token endpoint requests have proper observability metric headers
                $this->assertStringContainsString(
                    sprintf('%s %s cred-type/%s', $this->langAndVersion, $requestTypeHeaderValue, $credShortform),
                    $request->getHeaderLine(self::$headerKey)
                );
                return new Response(200, [], Utils::streamFor($jsonTokens));
            }
        ]);
    }

    public function tokenRequestType()
    {
        return [
            ['someScope', null, 'auth-request-type/at'],
            [null, 'someTargetAudience', 'auth-request-type/it'],
        ];
    }
}
