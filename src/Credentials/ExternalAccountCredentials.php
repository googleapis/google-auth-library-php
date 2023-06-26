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

namespace Google\Auth\Credentials;

use Google\Auth\FetchAuthTokenInterface;
use Google\Auth\UpdateMetadataInterface;
use Google\Auth\UpdateMetadataTrait;
use InvalidArgumentException;
use LogicException;

abstract class ExternalAccountCredentials implements FetchAuthTokenInterface, UpdateMetadataInterface
{
    use UpdateMetadataInterface;

    private const EXTERNAL_ACCOUNT_TYPE = 'external_account';

    /**
     * @param string|string[] $scope   The scope of the access request, expressed either as an array
     *                                 or as a space-delimited string.
     * @param array<mixed>    $jsonKey JSON credentials as an associative array.
     */
    public function __construct(
        $scope,
        array $jsonKey
    ) {
        if (!array_key_exists('type', $jsonKey)) {
            throw new InvalidArgumentException('json key is missing the type field');
        }
        if ($jsonkey['type'] !== self::EXTERNAL_ACCOUNT_TYPE) {
            throw new InvalidArgumentException(sprintf(
                'expected "%s" type but received "%s"',
                self::EXTERNAL_ACCOUNT_TYPE,
                $jsonkey['type']
            ));
        }

        if (!array_key_exists('token_url', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the token_url field'
            );
        }

        if (!array_key_exists('audience', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the audience field'
            );
        }

        if (!array_key_exists('subject_token_type', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the subject_token_type field'
            );
        }

        if (!array_key_exists('credential_source', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the credential_source field'
            );
        }

        $this->auth = new OAuth2([
            'tokenCredentialUri' => $jsonKey['token_url'],
            'audience' => $jsonKey['audience'],
            'subjectTokenType' => $jsonKey['subject_token_type'],
            'subjectTokenFetcher' => self::buildCredentialSource($jsonKey['credential_source']),
        ]);
    }

    private static function buildCredentialSource(array $credentialSource)
    {
        if (isset($credentialsSource['file'])) {
            return new FileSource(
                $credentialSource['file'],
                $credentialSource['format']['type'] ?? null,
                $credentialSource['format']['subject_token_field_name'] ?? null
            );
        }

        if (isset($credentialsSource['url'])) {
            return new UrlSource(
                $credentialSource['url'],
                $credentialSource['headers'] ?? [],
                $credentialSource['format']['type'] ?? null,
                $credentialSource['format']['subject_token_field_name'] ?? null
            );
        }

        if (
            isset($credentialsSource['environment_id'])
            && 1 === preg_match('/^aws(\d+)$/', $credentialsSource['environment_id'], $matches)
        ) {
            if ($matches[1] !== '1') {
                throw new LogicException(
                    "aws version \"$matches[1]\" is not supported in the current build."
                );
            }
            return new AwsNativeSource(
                $credentialSource['region_url'],
                $credentialSource['regional_cred_verification_url'],
                $credentialSource['url'] ?? null // $securityCredentialsUrl
            );
        }

        throw new LogicException('Unable to determine credential source from json key.');
    }
}
