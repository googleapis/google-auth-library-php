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
use LogicException;

/**
 * Provides a set of credentials that will always return an empty access token.
 * This is useful for APIs which do not require authentication, for local
 * service emulators, and for testing.
 */
class OAuth2Credentials implements CredentialsInterface
{
    use CredentialsTrait;

    /**
     * @var \Google\Auth\OAuth2
     */
    private $oauth2;

    /**
     * @param OAuth2 $oauth2
     * @param array  $options
     */
    public function __construct(OAuth2 $oauth2, array $options = [])
    {
        $this->setCacheFromOptions($options);

        $this->oauth2 = $oauth2;
    }

    /**
     * Get the project ID.
     *
     * @return null|string
     */
    public function getProjectId(): ?string
    {
        throw new LogicException(
            'getProjectId is not implemented for OAuth2 credentials'
        );
    }

    /**
     * Get the quota project used for this API request.
     *
     * @return null|string
     */
    public function getQuotaProject(): ?string
    {
        throw new LogicException(
            'getQuotaProject is not implemented for OAuth2 credentials'
        );
    }

    /**
     * Fetches the auth tokens based on the current state.
     *
     * @return array a hash of auth tokens
     */
    private function fetchAuthTokenNoCache(): array
    {
        return $this->oauth2->fetchAuthToken();
    }

    /**
     * Obtains a key that can used to cache the results of #fetchAuthToken.
     *
     * The key is derived from the scopes.
     *
     * @return string a key that may be used to cache the auth token
     */
    private function getCacheKey(): string
    {
        if ($cacheKey = $this->oauth2->getCacheKey()) {
            return $cacheKey;
        }

        // If no scope and no audience, return default string.
        return 'oauth2_credentials_cache';
    }
}
