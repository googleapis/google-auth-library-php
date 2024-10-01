<?php

/*
 * Copyright 2022 Google Inc.
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

namespace Google\Auth\Tests\Credentials;

use Google\Auth\Credentials\ImpersonatedServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\UserRefreshCredentials;
use LogicException;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class ImpersonatedServiceAccountCredentialsTest extends TestCase
{
    private const SCOPE = ['scope/1', 'scope/2'];

    /**
     * @dataProvider provideServiceAccountImpersonationJson
     */
    public function testGetServiceAccountNameEmail(array $testJson)
    {
        $creds = new ImpersonatedServiceAccountCredentials(self::SCOPE, $testJson);
        $this->assertEquals('test@test-project.iam.gserviceaccount.com', $creds->getClientName());
    }

    /**
     * @dataProvider provideServiceAccountImpersonationJson
     */
    public function testGetServiceAccountNameID(array $testJson)
    {
        $testJson['service_account_impersonation_url'] = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/1234567890987654321:generateAccessToken';
        $creds = new ImpersonatedServiceAccountCredentials(self::SCOPE, $testJson);
        $this->assertEquals('1234567890987654321', $creds->getClientName());
    }

    /**
     * @dataProvider provideServiceAccountImpersonationJson
     */
    public function testErrorCredentials(array $testJson)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('json key is missing the service_account_impersonation_url field');

        new ImpersonatedServiceAccountCredentials(self::SCOPE, $testJson['source_credentials']);
    }

    /**
     * @dataProvider provideServiceAccountImpersonationJson
     */
    public function testSourceCredentialsFromJsonFiles(array $testJson, string $credClass)
    {
        $creds = new ImpersonatedServiceAccountCredentials(['scope/1', 'scope/2'], $testJson);

        $sourceCredentialsProperty = (new ReflectionClass($creds))->getProperty('sourceCredentials');
        $sourceCredentialsProperty->setAccessible(true);
        $this->assertInstanceOf($credClass, $sourceCredentialsProperty->getValue($creds));
    }

    public function provideServiceAccountImpersonationJson()
    {
        return [
            [$this->createUserISACTestJson(), UserRefreshCredentials::class],
            [$this->createSAISACTestJson(), ServiceAccountCredentials::class],
        ];
    }

    // Creates a standard JSON auth object for testing.
    private function createUserISACTestJson()
    {
        return [
            'type' => 'impersonated_service_account',
            'service_account_impersonation_url' => 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@test-project.iam.gserviceaccount.com:generateAccessToken',
            'source_credentials' => [
                'client_id' => 'client123',
                'client_secret' => 'clientSecret123',
                'refresh_token' => 'refreshToken123',
                'type' => 'authorized_user',
            ]
        ];
    }

    // Creates a standard JSON auth object for testing.
    private function createSAISACTestJson()
    {
        return [
            'type' => 'impersonated_service_account',
            'service_account_impersonation_url' => 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@test-project.iam.gserviceaccount.com:generateAccessToken',
            'source_credentials' => [
                'client_email' => 'clientemail@clientemail.com',
                'private_key' => 'privatekey123',
                'type' => 'service_account',
            ]
        ];
    }

}
