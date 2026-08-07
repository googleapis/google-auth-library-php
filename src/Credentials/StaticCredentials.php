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

use Google\Auth\FetchAuthTokenInterface;
use InvalidArgumentException;

/**
 * Provides a set of credentials that always returns a pre-issued access token.
 *
 * No token exchange or HTTP request is ever performed; the supplied token is
 * returned as-is. This is useful for development and testing, or when an access
 * token has already been obtained through some other means and simply needs to
 * be handed to the auth middleware.
 *
 * ```
 * use Google\Auth\Credentials\StaticCredentials;
 * use Google\Auth\Middleware\AuthTokenMiddleware;
 *
 * $creds = new StaticCredentials('ya29.my-access-token');
 * $middleware = new AuthTokenMiddleware($creds);
 * ```
 */
class StaticCredentials implements FetchAuthTokenInterface
{
    /**
     * @var array{access_token: string, expires_at: int}
     */
    private array $token;

    /**
     * @param string $accessToken The pre-issued OAuth2 access token to use.
     * @param int $expiresIn [optional] The lifetime of the token in seconds, used
     *     to populate its expiration. Defaults to 3600 (one hour).
     */
    public function __construct(string $accessToken, int $expiresIn = 3600)
    {
        if ($accessToken === '') {
            throw new InvalidArgumentException('The access token must not be empty');
        }

        $this->token = [
            'access_token' => $accessToken,
            'expires_at' => time() + $expiresIn,
        ];
    }

    /**
     * Returns the static access token supplied to the constructor.
     *
     * @param callable|null $httpHandler Unused; present for interface compatibility.
     * @return array{access_token: string, expires_at: int}
     */
    public function fetchAuthToken(?callable $httpHandler = null)
    {
        return $this->token;
    }

    /**
     * Returns a cache key derived from the supplied token. Caching a static token
     * has no real benefit, but a stable, token-specific key ensures a shared cache
     * pool never returns another credential's token.
     *
     * @return string
     */
    public function getCacheKey()
    {
        return 'static_credentials_' . md5($this->token['access_token']);
    }

    /**
     * @return array{access_token: string, expires_at: int}
     */
    public function getLastReceivedToken()
    {
        return $this->token;
    }
}
