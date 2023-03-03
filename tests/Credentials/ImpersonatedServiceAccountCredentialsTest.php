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
use LogicException;
use PHPUnit\Framework\TestCase;

class ImpersonatedServiceAccountCredentialsTest extends TestCase
{
    // Creates a standard JSON auth object for testing.
    private function createISACTestJson()
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

    public function testGetServiceAccountNameEmail()
    {
        $testJson = $this->createISACTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sa = new ImpersonatedServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertEquals('test@test-project.iam.gserviceaccount.com', $sa->getClientName());
    }

    public function testGetServiceAccountNameID()
    {
        $testJson = $this->createISACTestJson();
        $testJson['service_account_impersonation_url'] = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/1234567890987654321:generateAccessToken';
        $scope = ['scope/1', 'scope/2'];
        $sa = new ImpersonatedServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertEquals('1234567890987654321', $sa->getClientName());
    }

    public function testErrorCredentials()
    {
        $testJson = $this->createISACTestJson();
        $scope = ['scope/1', 'scope/2'];
        $this->expectException(LogicException::class);
        new ImpersonatedServiceAccountCredentials($scope, $testJson['source_credentials']);
    }
}
