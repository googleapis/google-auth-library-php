<?php
/*
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

namespace Google\Auth\Tests\CredentialSource;

use Google\Auth\Credentials\ExternalAccountCredentials;
use Google\Auth\CredentialSource\X509Source;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

class X509SourceTest extends TestCase
{
    private $x509Json;

    public function setUp(): void
    {
        $this->x509Json = [
            'type' => 'external_account',
            'audience' => '//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/providers/provider',
            'subject_token_type' => 'urn:ietf:params:oauth:token-type:mtls',
            'token_url' => 'https://sts.mtls.googleapis.com/v1/token',
            'credential_source' => [
                'certificate' => [
                    'certificate_config_location' => __DIR__ . '/../fixtures/fixtures8/cert_config.json',
                    'trust_chain_path' => __DIR__ . '/../fixtures/fixtures8/intermediate.crt',
                ]
            ]
        ];
    }

    public function testPemToDerB64ConversionIsCorrect()
    {
        // Get the expected output. We know that for a PEM file, the content
        // between the headers is the base64-encoded DER. Our pemToDerB64 function
        // decodes this, then re-encodes it. So the output should be the same as the input.
        $pemContent = file_get_contents(__DIR__ . '/../fixtures/fixtures8/leaf.crt');
        preg_match('/-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----/s', $pemContent, $matches);
        $expectedDerB64 = base64_encode(base64_decode($matches[1]));

        // Get the actual output from our PHP function
        $source = new X509Source(
            $this->x509Json['credential_source']['certificate']['certificate_config_location'],
            $this->x509Json['credential_source']['certificate']['trust_chain_path'],
        );
        $pemToDerB64 = new ReflectionMethod(X509Source::class, 'pemToDerB64');
        $pemToDerB64->setAccessible(true);
        $actualDerB64 = $pemToDerB64->invoke($source, $pemContent);

        // Assert they are identical
        $this->assertEquals($expectedDerB64, $actualDerB64);
    }

    public function testFetchSubjectTokenFormatIsCorrect()
    {
        // Calculate the expected base64(DER) strings
        $leafPem = file_get_contents(__DIR__ . '/../fixtures/fixtures8/leaf.crt');
        preg_match('/-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----/s', $leafPem, $leafMatches);
        $leafDerB64 = base64_encode(base64_decode($leafMatches[1]));

        $intermediatePem = file_get_contents(__DIR__ . '/../fixtures/fixtures8/intermediate.crt');
        preg_match('/-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----/s', $intermediatePem, $intermediateMatches);
        $intermediateDerB64 = base64_encode(base64_decode($intermediateMatches[1]));

        // Construct the expected final JSON string
        $expectedJson = json_encode([$leafDerB64, $intermediateDerB64]);

        // Get the actual subject token from our PHP code
        $creds = new ExternalAccountCredentials('scope', $this->x509Json);
        $reflection = new \ReflectionClass($creds);
        $authProperty = $reflection->getProperty('auth');
        $authProperty->setAccessible(true);
        $auth = $authProperty->getValue($creds);
        $actualSubjectToken = $auth->getSubjectTokenFetcher()->fetchSubjectToken();

        // Assert they are identical
        $this->assertEquals($expectedJson, $actualSubjectToken);
    }

    public function testConstructorThrowsExceptionWhenConfigDoesNotExist()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Certificate config file does not exist');

        new X509Source('nonexistent_config_file.json', null);
    }

    public function testConstructorThrowsExceptionWhenConfigIsInvalid()
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'gauth_');
        file_put_contents($tmpFile, json_encode(['foo' => 'bar']));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Certificate config is invalid');

        try {
            new X509Source($tmpFile, null);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testConstructorThrowsExceptionWhenCertFileDoesNotExist()
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'gauth_');
        $config = [
            'cert_configs' => [
                'workload' => [
                    'key_path' => 'nonexistent_key_path.key',
                    'cert_path' => 'nonexistent_cert_path.crt',
                ]
            ]
        ];
        file_put_contents($tmpFile, json_encode($config));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('cert_path file does not exist: nonexistent_cert_path.crt');

        try {
            new X509Source($tmpFile, null);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testConstructorThrowsExceptionWhenKeyFileDoesNotExist()
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'gauth_');
        $config = [
            'cert_configs' => [
                'workload' => [
                    'key_path' => 'nonexistent_key_path.key',
                    'cert_path' => __DIR__ . '/../fixtures/fixtures8/leaf.crt',
                ]
            ]
        ];
        file_put_contents($tmpFile, json_encode($config));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('key_path file does not exist: nonexistent_key_path.key');

        try {
            new X509Source($tmpFile, null);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testConstructorThrowsExceptionWhenTrustChainPathIsInvalid()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Trust chain path is invalid');

        new X509Source(
            __DIR__ . '/../fixtures/fixtures8/cert_config.json',
            'nonexistent_trust_chain.crt'
        );
    }
}
