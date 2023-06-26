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

namespace Google\Auth\CredentialSource;

use Google\Auth\FetchAuthTokenInterface;
use GuzzleHttp\Psr7\Request;

/**
 * Authenticates requests using IAM credentials.
 */
class AwsNativeSource implements FetchAuthTokenInterface
{
    private string $regionUrl;
    private string $regionalCredVerificationUrl;
    private ?string $securityCredentialsUrl;

    public function __construct(
        string $regionUrl,
        string $regionalCredVerificationUrl = null,
        string $securityCredentialsUrl = null
    ) {
        $this->regionUrl = $regionUrl;
        $this->regionalCredVerificationUrl = $regionalCredVerificationUrl;
        $this->securityCredentialsUrl = $securityCredentialsUrl;
    }

    public function fetchToken(callable $httpHandler = null): string
    {
        if (is_null($httpHandler)) {
            $httpHandler = HttpHandlerFactory::build(HttpClientCache::getHttpClient());
        }

        $region = $this->getRegion($httpHandler);
        $signingVars = $this->securityCredentialsUrl
            ? $this->getSigningVarsFromUrl($httpHandler, $this->securityCredentialsUrl)
            : $this->getSigningVarsFromEnv();
        if (is_null($signingVars)) {
            throw new \LogicException('Unable to get credentials from ENV, and no security credentials URL provided');
        }

        // From here we use an AwsRequestSigner or something along these lines to receive a token
        // TODO: Implement this logic
        throw new Exception('Not implemented');
    }

    private function getRegion(callable $httpHandler): string
    {
        // get the region/zone from the region URL
        $regionRequest = new Request($this->regionUrl, 'GET');
        $regionResponse = $httpHandler($regionRequest);

        // Remove last character. For example, if us-east-2b is returned,
        // the region would be us-east-2.
        return substr((string) $regionResponse->getBody(), 0, -1);
    }

    private function getSigningVarsFromUrl(callable $httpHandler, string $url): array
    {
        // Get the AWS role name
        $roleRequest = new Request($this->securityCredentialsUrl, 'GET');
        $roleResponse = $httpHandler($roleRequest);
        $roleName = (string) $roleResponse->getBody();

        // Get the AWS credentials
        $credsRequest = new Request(
            $this->securityCredentialsUrl . '/' . $roleName,
            'GET'
        );
        $credsResponse = $httpHandler($credsRequest);
        $awsCreds = json_decode((string) $credsResponse->getBody(), true);
        return [
            'accessKeyId' => $awsCreds['AccessKeyId'],
            'secretAccessKey' => $awsCreds['SecretAccessKey'],
            'token' => $awsCreds['Token'],
        ];
    }

    private function getSigningVarsFromEnv(): ?array
    {
        if (isset($_ENV['AWS_ACCESS_KEY_ID'])
            && isset($_ENV['AWS_SECRET_ACCESS_KEY'])
        ) {
            return [
                'accessKeyId' => $_ENV['AWS_ACCESS_KEY_ID'],
                'secretAccessKey' => $_ENV['AWS_SECRET_ACCESS_KEY'],
                'token' => $_ENV['AWS_SESSION_TOKEN'],
            ];
        }

        return null;
    }

    public function getCacheKey()
    {
        return '';
    }

    public function getLastReceivedToken()
    {
        return '';
    }
}
