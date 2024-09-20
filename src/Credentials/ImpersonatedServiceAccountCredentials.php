<?php

/*
 * Copyright 2022 Google Inc.
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

namespace Google\Auth\Credentials;

use Exception;
use Google\Auth\CredentialsLoader;
use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use Google\Auth\IamSignerTrait;
use Google\Auth\OAuth2;
use Google\Auth\SignBlobInterface;
use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;

class ImpersonatedServiceAccountCredentials extends CredentialsLoader implements SignBlobInterface
{
    use IamSignerTrait;

    private const CRED_TYPE = 'imp';

    /**
     * @var string
     */
    protected string $impersonatedServiceAccountName;

    /**
     * @var UserRefreshCredentials
     */
    protected UserRefreshCredentials $sourceCredentials;

    /**
     * @var array{target_audience?: string} Additional claims for the id token
     */
    protected array $additionalClaims;

    /**
     * Instantiate an instance of ImpersonatedServiceAccountCredentials from a credentials file that
     * has be created with the --impersonated-service-account flag.
     *
     * @param string|string[]|null $scope The scope of the access request, expressed either as an
     *   array or as a space-delimited string.
     * @param string|array<mixed> $jsonKey JSON credential file path or JSON credentials
     *   as an associative array.
     * @param string|null $sub an email address account to impersonate, in situations when
     *    the service account has been delegated domain wide access.
     * @param string|null $targetAudience The audience for the ID token.
     */
    public function __construct(
        string|array|null $scope,
        string|array $jsonKey,
        // sub is currently not implemented but specified to keep the order of arguments
        // the same as ServiceAccountCredentials
        string $sub = null,
        string $targetAudience = null
    ) {
        if (is_string($jsonKey)) {
            if (!file_exists($jsonKey)) {
                throw new \InvalidArgumentException('file does not exist');
            }
            $json = file_get_contents($jsonKey);
            if (!$jsonKey = json_decode((string) $json, true)) {
                throw new \LogicException('invalid json for auth config');
            }
        }
        if (!array_key_exists('service_account_impersonation_url', $jsonKey)) {
            throw new \LogicException(
                'json key is missing the service_account_impersonation_url field'
            );
        }
        if (!array_key_exists('source_credentials', $jsonKey)) {
            throw new \LogicException('json key is missing the source_credentials field');
        }

        if ($scope && $targetAudience) {
            throw new InvalidArgumentException(
                'Scope and targetAudience cannot both be supplied'
            );
        }

        $this->impersonatedServiceAccountName = $this->getImpersonatedServiceAccountNameFromUrl(
            $jsonKey['service_account_impersonation_url']
        );

        $this->additionalClaims = [];
        if ($targetAudience) {
            $this->additionalClaims = ['target_audience' => $targetAudience];
        }

        $this->sourceCredentials = new UserRefreshCredentials(
            $scope,
            $jsonKey['source_credentials']
        );
    }

    /**
     * Helper function for extracting the Server Account Name from the URL saved in the account
     * credentials file.
     *
     * @param $serviceAccountImpersonationUrl string URL from "service_account_impersonation_url"
     * @return string Service account email or ID.
     */
    private function getImpersonatedServiceAccountNameFromUrl(
        string $serviceAccountImpersonationUrl
    ): string {
        $fields = explode('/', $serviceAccountImpersonationUrl);
        $lastField = end($fields);
        $splitter = explode(':', $lastField);
        return $splitter[0];
    }

    /**
     * Get the client name from the keyfile
     *
     * In this implementation, it will return the issuers email from the oauth token.
     *
     * @param callable|null $unusedHttpHandler not used by this credentials type.
     * @return string Token issuer email
     */
    public function getClientName(callable $unusedHttpHandler = null)
    {
        return $this->impersonatedServiceAccountName;
    }

    /**
     * Get an auth token.
     *
     * @param callable $httpHandler
     * @return array<mixed> {
     *     A set of auth related metadata, containing the following
     *
     *     @type string $access_token
     *     @type int $expires_in
     *     @type string $scope
     *     @type string $token_type
     *     @type ?string $id_token
     * }
     * @throws Exception
     */
    public function fetchAuthToken(callable $httpHandler = null): array
    {
        $tokens = $this->sourceCredentials->fetchAuthToken(
            $httpHandler,
            $this->applyTokenEndpointMetrics([], 'at')
        );

        // the authRequestType='it' does not work
        // fetch an id token using the access token from iam credentials
        if (array_key_exists('target_audience', $this->additionalClaims)) {
            if (is_null($httpHandler)) {
                $httpHandler = HttpHandlerFactory::build(HttpClientCache::getHttpClient());
            }

            $impersonatedServiceAccount = $this->getClientName();
            $request = new Request(
                'POST',
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{$impersonatedServiceAccount}:generateIdToken",
                [
                    'Authorization' => "Bearer {$tokens['access_token']}",
                    'Cache-Control' => 'no-store',
                    'Content-Type' => 'application/json',
                ],
                json_encode([
                    'audience' => $this->additionalClaims['target_audience'],
                    'includeEmail' => true,
                ])
            );
            $body = (string) $httpHandler($request)->getBody();

            // Assume it's JSON; if it's not throw an exception
            if (null === $res = json_decode($body, true)) {
                throw new Exception('Invalid JSON response');
            }
            // we cannot append the id_token to the list of tokens already fetched
            // as the AuthTokenMiddleware will first try to set the access_token if
            // it can find it.
            $tokens = ['id_token' => $res['token']];
        }

        return $tokens;
    }

    /**
     * Returns the Cache Key for the credentials
     * The cache key is the same as the UserRefreshCredentials class
     *
     * @return string
     */
    public function getCacheKey()
    {
        return $this->sourceCredentials->getCacheKey();
    }

    /**
     * @return array<mixed>
     */
    public function getLastReceivedToken()
    {
        return $this->sourceCredentials->getLastReceivedToken();
    }

    protected function getCredType(): string
    {
        return self::CRED_TYPE;
    }
}
