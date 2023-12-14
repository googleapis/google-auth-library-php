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

    private static array $requestType = [
        'accessToken' => 'auth-request-type/at',
        'idToken' => 'auth-request-type/idt',
        'mdsPing' => 'auth-request-type/mds'
    ];

    private static array $credType = [
        'user' => 'cred-type/u',
        'sa' => 'cred-type/sa',
        'sa-jwt' => 'cred-type/jwt',
        'gce' => 'cred-type/mds',
        'impersonate' => 'cred-type/imp'
    ];

    private function getVersion(): string
    {
        if (is_null(self::$version)) {
            $versionFilePath = implode(DIRECTORY_SEPARATOR, [__DIR__, '..', 'VERSION']);
            self::$version = trim((string) file_get_contents($versionFilePath));
        }
        return self::$version;
    }


}
