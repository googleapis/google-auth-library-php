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

namespace Google\Auth;

/**
 * Trait containing helper methods required for enabling
 * observability metrics in the library.
 *
 * @internal
 */
trait MetricsTrait
{
    /**
     * @var string The version of the auth library php.
     */
    private static $version;

    /**
     * @var string The header key for the observability metrics.
     */
    protected static $metricsHeaderKey = 'x-goog-api-client';

    /**
     * @var array<string, string> The request type header values
     *      for the observability metrics.
     */
    private static $requestType = [
        'accessToken' => 'auth-request-type/at',
        'idToken' => 'auth-request-type/it',
    ];

    /**
     * @var array<string, string> The credential type headervalues
     *      for the observability metrics.
     */
    private static $credTypes = [
        'user' => 'cred-type/u',
        'sa' => 'cred-type/sa',
        'jwt' => 'cred-type/jwt',
        'gce' => 'cred-type/mds',
        'impersonate' => 'cred-type/imp'
    ];

    /**
     * @var string The credential type for the observability metrics.
     *      This would be overridden by the credential class if applicable.
     */
    protected $credType = '';

    protected function getServiceApiMetricsHeaderValue(): string
    {
        if (!empty($this->credType)) {
            return $this->langAndVersion() . ' ' . $this->credType;
        }
        return '';
    }

    protected function getTokenEndpointMetricsHeaderValue(bool $isAccessTokenRequest): string
    {
        $value = $this->langAndVersion();
        $value .= ' ' . self::$requestType[($isAccessTokenRequest ? 'accessToken' : 'idToken')];

        if (!empty($this->credType)) {
            return $value . ' ' . $this->credType;
        }

        return '';
    }

    /**
     * @param array<mixed> $metadata The metadata to update and return.
     * @param string $headerValue The header value to add to the metadata for
     *        observability metrics.
     * @return array<mixed> The updated metadata.
     */
    protected function applyMetricsHeader($metadata, $headerValue)
    {
        if (empty($headerValue)) {
            return $metadata;
        } elseif (!isset($metadata[self::$metricsHeaderKey]) || empty($metadata[self::$metricsHeaderKey])) {
            $metadata[self::$metricsHeaderKey] = [$headerValue];
        } elseif (is_array($metadata[self::$metricsHeaderKey])) {
            $metadata[self::$metricsHeaderKey][0] .= ' ' . $headerValue;
        } else {
            // It's a string instead of array
            $metadata[self::$metricsHeaderKey] .= ' ' . $headerValue;
        }

        return $metadata;
    }

    protected static function getVersion(): string
    {
        if (is_null(self::$version)) {
            $versionFilePath = implode(DIRECTORY_SEPARATOR, [__DIR__, '..', 'VERSION']);
            self::$version = trim((string) file_get_contents($versionFilePath));
        }
        return self::$version;
    }

    private function langAndVersion(): string
    {
        return 'gl-php/' . PHP_VERSION . ' auth/' . self::getVersion();
    }
}
