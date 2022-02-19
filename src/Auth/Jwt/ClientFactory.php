<?php
/**
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

declare(strict_types=1);

namespace Google\Auth\Jwt;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Google\Jwt\Client\FirebaseClient;
use Google\Jwt\ClientInterface;

class ClientFactory
{
    /**
     * Builds out a default http client.
     *
     * @return ClientInterface
     */
    public static function build(): ClientInterface
    {
        return new FirebaseClient(new JWT(), new JWK());
    }
}
