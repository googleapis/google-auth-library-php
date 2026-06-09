<?php

/*
 * Copyright 2026 Google Inc.
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

use Google\Auth\CredentialsLoader;
use Google\Auth\GetQuotaProjectInterface;
use Google\Auth\GetUniverseDomainInterface;
use Google\Auth\OAuth2;
use InvalidArgumentException;

/**
 * Authenticates requests using External Account Authorized User credentials.
 *
 * This class allows authorizing requests from user refresh tokens sourced from
 * external accounts.
 */
class ExternalAccountAuthorizedUserCredentials extends CredentialsLoader implements GetQuotaProjectInterface
{
    /**
     * Used in observability metric headers
     *
     * @var string
     */
    private const CRED_TYPE = 'eaau';

    /**
     * The OAuth2 instance used to conduct authorization.
     */
    private OAuth2 $auth;

    private string $clientId;
    private string $clientSecret;
    private string $universeDomain;

    /**
     * The quota project associated with the JSON credentials
     */
    protected ?string $quotaProject = null;

    /**
     * Create a new ExternalAccountAuthorizedUserCredentials.
     *
     * @param string|string[]|null $scope the scope of the access request, expressed
     *   either as an Array or as a space-delimited String.
     * @param array<mixed> $jsonKey JSON credential file path or JSON credentials
     *   as an associative array
     */
    public function __construct(
        string|array|null $scope,
        array $jsonKey,
    ) {
        if (!array_key_exists('client_id', $jsonKey)) {
            throw new InvalidArgumentException(
                'json key is missing the client_id field'
            );
        }
        if (!array_key_exists('client_secret', $jsonKey)) {
            throw new InvalidArgumentException(
                'json key is missing the client_secret field'
            );
        }
        if (!array_key_exists('refresh_token', $jsonKey)) {
            throw new InvalidArgumentException(
                'json key is missing the refresh_token field'
            );
        }
        if (!array_key_exists('token_url', $jsonKey)) {
            throw new InvalidArgumentException(
                'json key is missing the token_url field'
            );
        }

        $this->clientId = $jsonKey['client_id'];
        $this->clientSecret = $jsonKey['client_secret'];
        $this->universeDomain = $jsonKey['universe_domain'] ?? GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN;
        $this->auth = new OAuth2([
            'refresh_token' => $jsonKey['refresh_token'],
            'tokenCredentialUri' => $jsonKey['token_url'],
            'scope' => $scope,
        ]);
        if (array_key_exists('quota_project_id', $jsonKey)) {
            $this->quotaProject = (string) $jsonKey['quota_project_id'];
        }
    }

    /**
     * @param callable|null $httpHandler
     * @param array<mixed> $headers
     *
     * @return array<mixed> {
     *     A set of auth related metadata, containing the following
     *
     *     @type string $access_token
     *     @type int $expires_in
     *     @type string $token_type
     * }
     */
    public function fetchAuthToken(?callable $httpHandler = null, array $headers = [])
    {
        $headers['Authorization'] = sprintf(
            'Basic %s',
            base64_encode($this->clientId . ':' . $this->clientSecret)
        );
        return $this->auth->fetchAuthToken(
            $httpHandler,
            $this->applyTokenEndpointMetrics($headers, 'at')
        );
    }

    /**
     * Return the Cache Key for the credentials.
     * The format for the Cache key is
     * Hash(ClientId.Scope.RefreshToken)
     *
     * @return string
     */
    public function getCacheKey()
    {
        return hash('sha256', implode('.', [
            $this->clientId,
            $this->auth->getScope(),
            $this->auth->getRefreshToken()
        ]));
    }

    /**
     * @return array<mixed>
     */
    public function getLastReceivedToken()
    {
        return $this->auth->getLastReceivedToken();
    }

    /**
     * Get the quota project used for this API request
     *
     * @return string|null
     */
    public function getQuotaProject(): string|null
    {
        return $this->quotaProject;
    }

    /**
     * Get the universe domain used for this API request
     *
     * @return string
     */
    public function getUniverseDomain(): string
    {
        return $this->universeDomain;
    }

    /**
     * Get the granted scopes (if they exist) for the last fetched token.
     *
     * @return string|null
     */
    public function getGrantedScope()
    {
        return $this->auth->getGrantedScope();
    }

    protected function getCredType(): string
    {
        return self::CRED_TYPE;
    }
}
