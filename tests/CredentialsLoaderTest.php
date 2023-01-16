<?php
/*
 * Copyright 2020 Google Inc.
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

namespace Google\Auth\Tests;

use Google\Auth\CredentialsLoader;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use UnexpectedValueException;

class CredentialsLoaderTest extends TestCase
{
    public function testUpdateMetadataSkipsWhenAuthenticationisSet()
    {
        $creds = new TestCredentialsLoader();
        $metadata = $creds->updateMetadata(['authentication' => 'foo']);
        $this->assertArrayHasKey('authentication', $metadata);
        $this->assertEquals('foo', $metadata['authentication']);
    }

    /** @runInSeparateProcess */
    public function testGetDefaultClientCertSource()
    {
        $_ENV['HOME'] = __DIR__ . '/fixtures4/valid';

        $callback = CredentialsLoader::getDefaultClientCertSource();
        $this->assertNotNull($callback);

        $output = $callback();
        $this->assertEquals('foo', $output);
    }

    /** @runInSeparateProcess */
    public function testNonExistantDefaultClientCertSource()
    {
        $_ENV['HOME'] = '';

        $callback = CredentialsLoader::getDefaultClientCertSource();
        $this->assertNull($callback);
    }

    /**
     * @runInSeparateProcess
     */
    public function testDefaultClientCertSourceInvalidJsonThrowsException()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid client cert source JSON');

        $_ENV['HOME'] = __DIR__ . '/fixtures4/invalidjson';

        CredentialsLoader::getDefaultClientCertSource();
    }

    /**
     * @runInSeparateProcess
     */
    public function testDefaultClientCertSourceInvalidKeyThrowsException()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('cert source requires "cert_provider_command"');

        $_ENV['HOME'] = __DIR__ . '/fixtures4/invalidkey';

        CredentialsLoader::getDefaultClientCertSource();
    }

    /**
     * @runInSeparateProcess
     */
    public function testDefaultClientCertSourceInvalidValueThrowsException()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('cert source expects "cert_provider_command" to be an array');

        $_ENV['HOME'] = __DIR__ . '/fixtures4/invalidvalue';

        CredentialsLoader::getDefaultClientCertSource();
    }

    /**
     * @runInSeparateProcess
     */
    public function testActualDefaultClientCertSource()
    {
        $clientCertSource = CredentialsLoader::getDefaultClientCertSource();
        if (is_null($clientCertSource)) {
            $this->markTestSkipped('No client cert source found');
        }
        $creds = $clientCertSource();
        $this->assertTrue(is_string($creds));
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $creds);
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $creds);
    }

    /**
     * @runInSeparateProcess
     */
    public function testDefaultClientCertSourceInvalidCmdThrowsException()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('"cert_provider_command" failed with a nonzero exit code');

        $_ENV['HOME'] = __DIR__ . '/fixtures4/invalidcmd';

        $callback = CredentialsLoader::getDefaultClientCertSource();

        // Close stderr so output doesnt show in our test runner
        fclose(STDERR);

        $callback();
    }

    /**
     * @runInSeparateProcess
     */
    public function testShouldLoadClientCertSourceInvalidValueIsFalse()
    {
        $_ENV[CredentialsLoader::MTLS_CERT_ENV_VAR] = 'foo';

        $this->assertFalse(CredentialsLoader::shouldLoadClientCertSource());
    }

    /**
     * @runInSeparateProcess
     */
    public function testShouldLoadClientCertSourceDefaultValueIsFalse()
    {
        unset($_ENV[CredentialsLoader::MTLS_CERT_ENV_VAR]);

        $this->assertFalse(CredentialsLoader::shouldLoadClientCertSource());
    }

    /**
     * @runInSeparateProcess
     */
    public function testShouldLoadClientCertSourceIsTrue()
    {
        $_ENV[CredentialsLoader::MTLS_CERT_ENV_VAR] = 'true';

        $this->assertTrue(CredentialsLoader::shouldLoadClientCertSource());
    }
}

class TestCredentialsLoader extends CredentialsLoader
{
    public function getCacheKey()
    {
        return 'test';
    }

    public function fetchAuthToken(callable $httpHandler = null)
    {
        return 'test';
    }

    public function getLastReceivedToken()
    {
        return null;
    }
}
