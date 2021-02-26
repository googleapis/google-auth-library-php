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

namespace Google\Auth\SignBlob;

use Google\Http\ClientInterface;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Utils;

/**
 * Tools for using the IAM API.
 *
 * @see https://cloud.google.com/iam/docs IAM Documentation
 *
 * @internal
 */
trait ServiceAccountApiSignBlobTrait
{
    /**
     * Sign a string using the IAM signBlob API.
     *
     * Note that signing using IAM requires your service account to have the
     * `iam.serviceAccounts.signBlob` permission, part of the "Service Account
     * Token Creator" IAM role.
     *
     * @param string $stringToSign the string to be signed
     * @param string $email        the service account email
     * @param string $accessToken  an access token from the service account
     * @param array  $delegates    [optional] A list of service account emails to
     *                             add to the delegate chain. If omitted, the value of `$email` will
     *                             be used.
     *
     * @return string the signed string, base64-encoded
     */
    private function signBlobWithServiceAccountApi(
        string $stringToSign,
        string $email,
        string $accessToken,
        ClientInterface $httpClient,
        array $delegates = []
    ): string {
        $name = sprintf('projects/-/serviceAccounts/%s', $email);
        $uri = sprintf(
            'https://iamcredentials.googleapis.com/v1/%s:signBlob?alt=json',
            $name
        );

        if ($delegates) {
            foreach ($delegates as &$delegate) {
                $delegate = sprintf('projects/-/serviceAccounts/%s', $delegate);
            }
        } else {
            $delegates = [$name];
        }

        $body = [
            'delegates' => $delegates,
            'payload' => base64_encode($stringToSign),
        ];

        $headers = [
            'Authorization' => 'Bearer ' . $accessToken,
        ];

        $request = new Psr7\Request(
            'POST',
            $uri,
            $headers,
            Utils::streamFor(json_encode($body))
        );

        $res = $httpClient->send($request);
        $body = json_decode((string) $res->getBody(), true);

        return $body['signedBlob'];
    }
}
