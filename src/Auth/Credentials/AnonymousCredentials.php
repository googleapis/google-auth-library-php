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

/**
 * Provides a set of credentials that will always return an empty access token.
 * This is useful for APIs which do not require authentication, for local
 * service emulators, and for testing.
 */
class AnonymousCredentials implements CredentialsInterface
{
    use CredentialsTrait;

    /**
     * @var array
     */
    private $token = [
        'access_token' => '',
    ];

    /**
     * Fetches the auth token. In this case it returns an empty string.
     *
     * @return array a hash of auth tokens
     */
    public function fetchAuthToken(): array
    {
        return $this->token;
    }

    /**
     * Get the project ID.
     *
     * @return null|string
     */
    public function getProjectId(): ?string
    {
        return null;
    }

    /**
     * Get the quota project used for this API request.
     *
     * @return null|string
     */
    public function getQuotaProject(): ?string
    {
        return null;
    }
}
