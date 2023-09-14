<?php
/*
 * Copyright 2023 Google LLC
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

namespace Google\Auth;

/**
 * Provides methods for fetching and updation of auth metrics headers.
 *
 * @internal
 */
trait MetricsTrait
{
    public const METRICS_HEADER_KEY = 'x-goog-api-client';

    // Auth request type
    public const REQUEST_TYPE_ACCESS_TOKEN = 'auth-request-type/at';
    public const REQUEST_TYPE_ID_TOKEN = 'auth-request-type/it';
    public const REQUEST_TYPE_MDS_PING = 'auth-request-type/mds';
    public const REQUEST_TYPE_REAUTH_START = 'auth-request-type/re-start';

    // Credential type
    public const CRED_TYPE_USER = 'cred-type/u';
    public const CRED_TYPE_SA_ASSERTION = 'cred-type/sa';
    public const CRED_TYPE_SA_JWT = 'cred-type/jwt';
    public const CRED_TYPE_SA_MDS = 'cred-type/mds';
    public const CRED_TYPE_SA_IMPERSONATE = 'cred-type/imp';

    // TODO: Find a way to get the auth version
    // Auth library version
    public const VERSION = '10.0.0';

    public function getPhpAndAuthLibVersion()
    {
        return 'gl-php/' . PHP_VERSION . ' auth/' . self::VERSION;
    }

    /**
     * Returns header string for token request with credentials obtained from
     * Google Compute Engine.
     *
     * @param bool $isAccessTokenRequest Determins whether the request is
     *             for access token or identity token. `true` returns headers
     *             for access token and `false` returns for identity tokens.
     * @return string
     */
    public function getTokenRequestMdsHeader(bool $isAccessTokenRequest)
    {
        return $this->getDefaults($isAccessTokenRequest) . ' ' . self::CRED_TYPE_SA_MDS;
    }

    /**
     * Returns header string for token request with Service Account Credentials.
     *
     * @param bool $isAccessTokenRequest Determins whether the request is
     *             for access token or identity token. `true` returns headers
     *             for access token and `false` returns for identity tokens.
     * @return string
     */
    public function getTokenRequestSaAssertionHeader(bool $isAccessTokenRequest)
    {
        return $this->getDefaults($isAccessTokenRequest) . ' ' . self::CRED_TYPE_SA_ASSERTION;
    }

    /**
     * Returns header string for token request with Impersonated Service Account Credentials.
     *
     * @param bool $isAccessTokenRequest Determins whether the request is
     *             for access token or identity token. `true` returns headers
     *             for access token and `false` returns for identity tokens.
     * @return string
     */
    public function getTokenRequestSaImpersonateHeader(bool $isAccessTokenRequest)
    {
        return $this->getDefaults($isAccessTokenRequest) . ' ' . self::CRED_TYPE_SA_IMPERSONATE;
    }

    /**
     * Returns header string for token request with User Refresh Credentials.
     *
     * @param bool $isAccessTokenRequest Determins whether the request is
     *             for access token or identity token. `true` returns headers
     *             for access token and `false` returns for identity tokens.
     * @return string
     */
    public function getTokenRequestUserHeader(bool $isAccessTokenRequest)
    {
        return $this->getDefaults($isAccessTokenRequest) . ' ' . self::CRED_TYPE_USER;
    }

    /**
     * Returns header string for metadata server ping request.
     */
    public function getMdsPingHeader()
    {
        return $this->getPhpAndAuthLibVersion()
            . ' ' . self::REQUEST_TYPE_MDS_PING;
    }

    /**
     * Apply the auth metrics header to `x-goog-api-client` key of the `$headers`
     * properly and return updated headers.
     *
     * @param array $headers The headers to update.
     * @param string $metricsHeaderToApply Auth metrics header value to apply
     * @return array Updated headers value.
     */
    public function applyAuthMetricsHeaders(array $headers, string $metricsHeaderToApply)
    {
        if ($metricsHeaderToApply == '') {
            return $headers;
        } else if (isset($headers[self::METRICS_HEADER_KEY])) {
            $headers[self::METRICS_HEADER_KEY][0] .= ' ' . $metricsHeaderToApply;
        } else {
            $headers[self::METRICS_HEADER_KEY] = [$metricsHeaderToApply];
        }
        return $headers;
    }

    private function getDefaults(bool $forAccessToken = true)
    {
        $result = $this->getPhpAndAuthLibVersion();
        if ($forAccessToken) {
            $result .= ' ' . self::REQUEST_TYPE_ACCESS_TOKEN;
        } else {
            $result .= ' ' . self::REQUEST_TYPE_ID_TOKEN;
        }
        return $result;
    }

}
