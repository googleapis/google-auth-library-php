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
 * Provides shared methods for updating request metadata (request headers).
 *
 * Should implement {@see UpdateMetadataInterface} and {@see FetchAuthTokenInterface}.
 *
 * @internal
 */
trait UpdateMetadataTrait
{
    /**
     * @var string The version of the auth library php.
     */
    private static $version;

    /**
     * export a callback function which updates runtime metadata.
     *
     * @return callable updateMetadata function
     * @deprecated
     */
    public function getUpdateMetadataFunc()
    {
        return [$this, 'updateMetadata'];
    }

    public function getCredType(): string
    {
        return '';
    }

    /**
     * Updates metadata with the authorization token.
     *
     * @param array<mixed> $metadata metadata hashmap
     * @param string $authUri optional auth uri
     * @param callable $httpHandler callback which delivers psr7 request
     * @return array<mixed> updated metadata hashmap
     */
    public function updateMetadata(
        $metadata,
        $authUri = null,
        callable $httpHandler = null
    ) {
        $metadata_copy = $metadata;

        if ($credType = $this->getCredType()) {
            // Add service api usage observability metrics info to metadata
            $metricsHeader = self::getMetricsHeader($credType);
            if (!isset($metadata_copy[self::METRIC_METADATA_KEY])) {
                $metadata_copy[self::METRIC_METADATA_KEY] = [$metricsHeader];
            } elseif (is_array($metadata_copy[self::METRIC_METADATA_KEY])) {
                $metadata_copy[self::METRIC_METADATA_KEY][0] .= ' ' . $metricsHeader;
            } else {
                $metadata_copy[self::METRIC_METADATA_KEY] .= ' ' . $metricsHeader;
            }
        }

        if (isset($metadata_copy[self::AUTH_METADATA_KEY])) {
            // Auth metadata has already been set
            return $metadata_copy;
        }
        $result = $this->fetchAuthToken($httpHandler);
        if (isset($result['access_token'])) {
            $metadata_copy[self::AUTH_METADATA_KEY] = ['Bearer ' . $result['access_token']];
        } elseif (isset($result['id_token'])) {
            $metadata_copy[self::AUTH_METADATA_KEY] = ['Bearer ' . $result['id_token']];
        }
        return $metadata_copy;
    }

    /**
     * @param string $credType [Optional] The credential type.
     *        Empty value will not add any credential type to the header.
     *        Should be one of `'sa'`, `'jwt'`, `'imp'`, `'mds'`, `'u'`.
     * @param string $authRequestType [Optional] The auth request type.
     *        Empty value will not add any auth request type to the header.
     *        Should be one of `'at'`, `'it'`, `'mds'`.
     * @return string The header value for the observability metrics.
     */
    protected static function getMetricsHeader(
        string $credType = '',
        string $authRequestType = ''
    ): string {
        $value = sprintf(
            'gl-php/%s auth/%s',
            PHP_VERSION,
            self::getVersion()
        );

        if (!empty($authRequestType)) {
            $value .= ' auth-request-type/' . $authRequestType;
        }

        if (!empty($credType)) {
            $value .= ' cred-type/' . $credType;
        }

        return $value;
    }

    protected static function getVersion(): string
    {
        if (is_null(self::$version)) {
            $versionFilePath = __DIR__ . '/../VERSION';
            self::$version = trim((string) file_get_contents($versionFilePath));
        }
        return self::$version;
    }
}
