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

    protected static function getMetricHeader(string $credType = '', string $authRequestType = ''): string
    {
        $value = sprintf('gl-php/%s auth/%s', PHP_VERSION, self::getVersion());

        if ($authRequestType) {
            $value .= ' auth-request-type/' . $authRequestType;
        }

        if ($credType) {
            $value .= ' cred-type/' . $credType;
        }

        return $value;
    }

    private static function getVersion(): string
    {
        if (is_null(self::$version)) {
            $versionFilePath = __DIR__ . '/../VERSION';
            self::$version = trim((string) file_get_contents($versionFilePath));
        }
        return self::$version;
    }

    /**
     * The credential type for the observability metrics.
     * This will be overridden by the credential class if applicable.
     */
    public function getCredType(): string
    {
        return '';
    }
}
