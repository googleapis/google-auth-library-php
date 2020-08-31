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

namespace Google\Auth;

/**
 * Implement logic to update metadata
 */
trait UpdateMetadataTrait
{
    /**
     * Updates metadata with the authorization token.
     *
     * @param array $metadata metadata hashmap
     * @param string $authUri optional auth uri
     * @param callable $httpHandler callback which delivers psr7 request
     * @return array updated metadata hashmap
     */
    public function updateMetadata(
        $metadata,
        $authUri = null,
        callable $httpHandler = null
    ) {
        if (isset($metadata[self::AUTH_METADATA_KEY])) {
            // Auth metadata has already been set
            return $metdadata;
        }
        $result = $this->fetchAuthToken($httpHandler);
        if (!isset($result['access_token'])) {
            return $metadata;
        }
        $metadata_copy = $metadata;
        $metadata_copy[self::AUTH_METADATA_KEY] = array('Bearer ' . $result['access_token']);

        return $metadata_copy;
    }
}
