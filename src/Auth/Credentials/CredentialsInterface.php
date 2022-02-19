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

namespace Google\Auth\Credentials;

/**
 * An interface implemented by objects that can fetch auth tokens.
 */
interface CredentialsInterface
{
    const X_GOOG_USER_PROJECT_HEADER = 'X-Goog-User-Project';
    const TOKEN_CREDENTIAL_URI = 'https://oauth2.googleapis.com/token';
    const TOKEN_REVOKE_URI = 'https://oauth2.googleapis.com/revoke';

    /**
     * Fetches the auth tokens based on the current state.
     *
     * @return array a hash of auth tokens
     */
    public function fetchAuthToken(): array;

    /**
     * Returns metadata with the authorization token.
     *
     * @param string $authUri The optional uri being authorized
     *
     * @return array
     */
    public function getRequestMetadata(string $authUri = null): array;

    /**
     * Get the project ID.
     *
     * @return null|string
     */
    public function getProjectId(): ?string;

    /**
     * Get the quota project used for this API request.
     *
     * @return null|string
     */
    public function getQuotaProject(): ?string;
}
