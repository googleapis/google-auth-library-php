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

namespace Google\Jwt\Client;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Google\Jwt\ClientInterface;
use Google\Jwt\VerificationFailedException;

class FirebaseClient implements ClientInterface
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

    /**
     * @throws VerificationFailedException
     */
    public function decode(string $jwt, array $keys, array $allowedAlgs): array
    {
        try {
            return (array) $this->jwt->decode($jwt, $keys, $allowedAlgs);
        } catch (BeforeValidException $e) {
            $code = VerificationFailedException::BEFORE_VALID;
        } catch (ExpiredException $e) {
            $code = VerificationFailedException::EXPIRED;
        } catch (SignatureInvalidException $e) {
            $code = VerificationFailedException::SIGNATURE_INVALID;
        }

        throw new VerificationFailedException($e->getMessage(), $code, $e);
    }

    public function parseKeySet(array $keySet): array
    {
        return $this->jwk->parseKeySet($keySet);
    }

    public function getExpirationWithoutVerification(string $jwt): ?int
    {
        $parts = \explode('.', $jwt);
        if (3 != \count($parts)) {
            throw new \InvalidArgumentException('Wrong number of segments');
        }

        list($headerB64, $payloadB64, $signatureB64) = $parts;

        $payload = $this->jwt->jsonDecode(
            $this->jwt->urlsafeB64Decode($payloadB64)
        );

        if (empty($payload->exp)) {
            return null;
        }

        if (!is_numeric($payload->exp)) {
            throw new \UnexpectedValueException('Expiration is not numeric');
        }

        return intval($payload->exp);
    }
}
