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

declare(strict_types=1);

namespace Google\Auth\Jwt;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

class FirebaseJwtClient implements JwtClientInterface
{
    private $jwt;
    private $jwk;

    public function __construct(JWT $jwt, JWK $jwk)
    {
        $this->jwt = $jwt;
        $this->jwk = $jwk;
    }

    public function encode(
        array $payload,
        string $signingKey,
        string $signingAlg,
        ?string $keyId
    ): string {
        return $this->jwt->encode($payload, $signingKey, $signingAlg, $keyId);
    }

    public function decode(string $jwt, array $keys, array $allowedAlgs): array
    {
        return (array) $this->jwt->decode($jwt, $keys, $allowedAlgs);
    }

    public function parseKeySet(array $keySet): array
    {
        return $this->jwk->parseKeySet($keySet);
    }
}
