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
    public static $metricsHeaderKey = 'x-goog-api-client';

    // Auth request type
    public static $requestTypeAccessToken = 'auth-request-type/at';
    public static $requestTypeIdToken = 'auth-request-type/it';
    public static $requestTypeMdsPing = 'auth-request-type/mds';

    // Credential type
    public static $credTypeUser = 'cred-type/u';
    public static $credTypeSaAssertion = 'cred-type/sa';
    public static $credTypeSaJwt = 'cred-type/jwt';
    public static $credTypeSaMds = 'cred-type/mds';
    public static $credTypeSaImpersonate = 'cred-type/imp';

    // TODO: Find a way to get the auth version
    // Auth library version
    public static $version = '10.0.0';

    public function getPhpAndAuthLibVersion()
    {
        return 'gl-php/' . PHP_VERSION . ' auth/' . self::$version;
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
        return $this->getDefaults($isAccessTokenRequest) . ' ' . self::$credTypeSaMds;
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
        return $this->getDefaults($isAccessTokenRequest) . ' ' . self::$credTypeSaAssertion;
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
        return $this->getDefaults($isAccessTokenRequest) . ' ' . self::$credTypeSaImpersonate;
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
        return $this->getDefaults($isAccessTokenRequest) . ' ' . self::$credTypeUser;
    }

    /**
     * Returns header string for metadata server ping request.
     */
    public function getMdsPingHeader()
    {
        return $this->getPhpAndAuthLibVersion()
            . ' ' . self::$requestTypeMdsPing;
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
        } elseif (isset($headers[self::$metricsHeaderKey])) {
            $headers[self::$metricsHeaderKey][0] .= ' ' . $metricsHeaderToApply;
        } else {
            $headers[self::$metricsHeaderKey] = [$metricsHeaderToApply];
        }
        return $headers;
    }

    private function getDefaults(bool $forAccessToken = true)
    {
        $result = $this->getPhpAndAuthLibVersion();
        if ($forAccessToken) {
            $result .= ' ' . self::$requestTypeAccessToken;
        } else {
            $result .= ' ' . self::$requestTypeIdToken;
        }
        return $result;
    }

}
