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
    private static $version = null;

    protected static $metricsHeaderKey = 'x-goog-api-client';

    private static array $requestType = [
        'accessToken' => 'auth-request-type/at',
        'idToken' => 'auth-request-type/it',
    ];

    private static array $credTypes = [
        'user' => 'cred-type/u',
        'sa' => 'cred-type/sa',
        'jwt' => 'cred-type/jwt',
        'gce' => 'cred-type/mds',
        'impersonate' => 'cred-type/imp'
    ];

    protected string $credType = '';
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
        if ($isAccessTokenRequest) {
            $value .= ' ' . self::$requestType['accessToken'];
        } else {
            $value .= ' ' . self::$requestType['idToken'];
        }

        if (!empty($this->credType)) {
            return $value . ' ' . $this->credType;
        }

        return '';
    }

    protected function applyMetricsHeader($metadata, $headerValue): array
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
