<?php
/*
 * Copyright 2020 Google LLC
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

declare(strict_types=1);

namespace Google\Auth\Credentials;

use Google\Auth\OAuth2;

/**
 * Authenticates requests using User Refresh credentials.
 *
 * This class allows authorizing requests from user refresh tokens.
 *
 * This the end of the result of a 3LO flow using the `gcloud` CLI.
 * 'gcloud auth login' saves a file with these contents in well known
 * location.
 *
 * @see [Application Default Credentials](http://goo.gl/mkAHpZ)
 */
class UserRefreshCredentials implements CredentialsInterface
{
    use CredentialsTrait;

    /**
     * The OAuth2 instance used to conduct authorization.
     *
     * @var OAuth2
     */
    private $oauth2;

    /**
     * The quota project associated with the JSON credentials.
     */
    private $quotaProject;

    /**
     * Create a new UserRefreshCredentials.
     *
     * @param array                  $jsonKey               JSON credential as an associative array
     * @param array                  $options
     * @param array                  $options.scope         the scope of the access request, expressed
     *                                                      either as an Array or as a space-delimited String
     * @param HttpClientInterface    $options.httpClient
     * @param CacheItemPoolInterface $options.cache
     * @param string                 $options.cachePrefix
     * @param int                    $options.cacheLifetime
     */
    public function __construct($jsonKey, array $options = [])
    {
        $options += [
            'scope' => null,
        ];

        $jsonKey = $this->parseJsonKey($jsonKey);

        if (!array_key_exists('client_id', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the client_id field'
            );
        }
        if (!array_key_exists('client_secret', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the client_secret field'
            );
        }
        if (!array_key_exists('refresh_token', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the refresh_token field'
            );
        }

        $this->setHttpClientFromOptions($options);
        $this->setCacheFromOptions($options);
        $this->throwExceptionForTargetAudience($options);

        $this->oauth2 = new OAuth2([
            'clientId' => $jsonKey['client_id'],
            'clientSecret' => $jsonKey['client_secret'],
            'refreshToken' => $jsonKey['refresh_token'],
            'scope' => $options['scope'] ?? null,
            'httpClient' => $this->httpClient,
            'tokenCredentialUri' => self::TOKEN_CREDENTIAL_URI,
        ]);
    }

    /**
     * Get the quota project used for this API request.
     *
     * @return null|string
     */
    public function getQuotaProject(): ?string
    {
        return $this->quotaProject;
    }

    /**
     * Get the project ID.
     *
     * @return null|string
     */
    public function getProjectId(): ?string
    {
        throw new \RuntimeException(
            'getProjectId is not implemented for user refresh credentials'
        );
    }

    /**
     * Returns an auth token with the following keys:
     *   - access_token (string)
     *   - expires_in   (int)
     *   - scope        (string)
     *   - token_type   (string)
     *
     * @return array auth token
     */
    private function fetchAuthTokenNoCache(): array
    {
        return $this->oauth2->fetchAuthToken();
    }

    /**
     * @return string
     */
    private function getCacheKey(): string
    {
        return $this->oauth2->getClientId() . ':' . $this->oauth2->getCacheKey();
    }
}
