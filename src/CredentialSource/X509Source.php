<?php
/**
 * Copyright 2026 Google Inc.
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
namespace Google\Auth\CredentialSource;

use Google\Auth\ExternalAccountCredentialSourceInterface;
use InvalidArgumentException;
use RuntimeException;

/**
 * A credential source for x509 client certificates.
 *
 * This class implements a non-standard mTLS flow where the client certificate
 * and chain are sent in a custom-formatted `subject_token` in the request body,
 * in addition to being used for the mTLS handshake at the transport layer.
 *
 * @internal
 */
class X509Source implements ExternalAccountCredentialSourceInterface
{
    private const BEGIN_CERT = '-----BEGIN CERTIFICATE-----';
    private const END_CERT = '-----END CERTIFICATE-----';

    private string $keyPath;
    private string $certPath;

    public function __construct(
        string $certificateConfigLocation,
        private string|null $trustChainPath,
    ) {
        if (!file_exists($certificateConfigLocation)) {
            throw new InvalidArgumentException('Certificate config file does not exist');
        }
        $config = json_decode((string) file_get_contents($certificateConfigLocation), true);
        if (!isset($config['cert_configs']['workload']['key_path'])
            || !isset($config['cert_configs']['workload']['cert_path'])
        ) {
            throw new InvalidArgumentException('Certificate config is invalid');
        }

        $this->keyPath = $config['cert_configs']['workload']['key_path'];
        $this->certPath = $config['cert_configs']['workload']['cert_path'];

        if (!file_exists($this->certPath)) {
            throw new InvalidArgumentException('cert_path file does not exist: ' . $this->certPath);
        }
        if (!file_exists($this->keyPath)) {
            throw new InvalidArgumentException('key_path file does not exist: ' . $this->keyPath);
        }
        if ($this->trustChainPath && !file_exists($this->trustChainPath)) {
            throw new InvalidArgumentException('Trust chain path is invalid');
        }
    }

    /**
     * Implements the custom subject token generation from the user's script.
     *
     * The subject token is a JSON array containing the base64-encoded DER
     * representation of the leaf and intermediate certs.
     */
    public function fetchSubjectToken(?callable $httpHandler = null): string
    {
        $certsB64Der = [];

        $leafCert = file_get_contents($this->certPath);
        if ($leafCert === false) {
            throw new InvalidArgumentException('Unable to read leaf certificate file.');
        }
        $certsB64Der[] = $this->pemToDerB64($leafCert);

        if ($this->trustChainPath && file_exists($this->trustChainPath)) {
            $intermediates = file_get_contents($this->trustChainPath);
            if ($intermediates === false) {
                throw new InvalidArgumentException('Unable to read intermediate certificate file.');
            }
            // The regex captures the full PEM blocks
            preg_match_all(
                '/' . self::BEGIN_CERT . '[\s\S]+?' . self::END_CERT . '/',
                $intermediates,
                $matches
            );

            foreach ($matches[0] as $pem) {
                $certsB64Der[] = $this->pemToDerB64($pem);
            }
        }

        $jsonCertArray = json_encode($certsB64Der);
        if ($jsonCertArray === false) {
            throw new RuntimeException('Failed to encode certificate array to JSON.');
        }
        return $jsonCertArray;
    }

    public function getCacheKey(): ?string
    {
        return null;
    }

    public function getCertPath(): string
    {
        return $this->certPath;
    }

    public function getKeyPath(): string
    {
        return $this->keyPath;
    }

    private function pemToDerB64(string $pem): string
    {
        $pattern = '/' . self::BEGIN_CERT . '\s*(.*?)\s*' . self::END_CERT . '/s';
        if (preg_match($pattern, $pem, $matches)) {
            $base64 = str_replace(["\n", "\r"], '', $matches[1]);
            $der = base64_decode($base64);
            if ($der === false) {
                throw new RuntimeException('Failed to base64-decode the certificate content.');
            }
            return base64_encode($der);
        }
        throw new RuntimeException('Failed to parse PEM certificate.');
    }
}
