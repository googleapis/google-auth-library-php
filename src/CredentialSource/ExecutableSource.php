<?php
/*
 * Copyright 2024 Google Inc.
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

use Google\Auth\ExecutableHandler\ExecutableHandler;
use Google\Auth\ExternalAccountCredentialSourceInterface;
use RuntimeException;
use UnexpectedValueException;

/**
 * ExecutableSource enables the exchange of workload identity pool external credentials for
 * Google access tokens by retrieving 3rd party tokens through a user supplied executable. These
 * scripts/executables are completely independent of the Google Cloud Auth libraries. These
 * credentials plug into ADC and will call the specified executable to retrieve the 3rd party token
 * to be exchanged for a Google access token.
 *
 * To use these credentials, the GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES environment variable
 * must be set to '1'. This is for security reasons.
 *
 * Both OIDC and SAML are supported. The executable must adhere to a specific response format
 * defined below.
 *
 * The executable must print out the 3rd party token to STDOUT in JSON format. When an
 * output_file is specified in the credential configuration, the executable must also handle writing the
 * JSON response to this file.
 *
 * <pre>
 * OIDC response sample:
 * {
 *   "version": 1,
 *   "success": true,
 *   "token_type": "urn:ietf:params:oauth:token-type:id_token",
 *   "id_token": "HEADER.PAYLOAD.SIGNATURE",
 *   "expiration_time": 1620433341
 * }
 *
 * SAML2 response sample:
 * {
 *   "version": 1,
 *   "success": true,
 *   "token_type": "urn:ietf:params:oauth:token-type:saml2",
 *   "saml_response": "...",
 *   "expiration_time": 1620433341
 * }
 *
 * Error response sample:
 * {
 *   "version": 1,
 *   "success": false,
 *   "code": "401",
 *   "message": "Error message."
 * }
 * </pre>
 *
 * The "expiration_time" field in the JSON response is only required for successful
 * responses when an output file was specified in the credential configuration
 *
 * The auth libraries will populate certain environment variables that will be accessible by the
 * executable, such as: GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE, GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE,
 * GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE, GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL, and
 * GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE.
 */
class ExecutableSource implements ExternalAccountCredentialSourceInterface
{
    private const GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES = 'GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES';
    private const SAML_SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:saml2';
    private const OIDC_SUBJECT_TOKEN_TYPE1 = 'urn:ietf:params:oauth:token-type:id_token';
    private const OIDC_SUBJECT_TOKEN_TYPE2 = 'urn:ietf:params:oauth:token-type:jwt';

    private string $command;
    private ExecutableHandler $executableHandler;
    private ?string $outputFile;

    /**
     * @param string $command    The string command to run to get the subject token.
     * @param string $outputFile
     */
    public function __construct(
        string $command,
        ?string $outputFile,
        ExecutableHandler $executableHandler = null,
    ) {
        $this->command = $command;
        $this->outputFile = $outputFile;
        $this->executableHandler = $executableHandler ?: new ExecutableHandler();
    }

    /**
     * @param callable $httpHandler unused.
     */
    public function fetchSubjectToken(callable $httpHandler = null): string
    {
        // Check if the executable is allowed to run.
        if (getenv(self::GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES) !== '1') {
            throw new RuntimeException(
                'Pluggable Auth executables need to be explicitly allowed to run by '
                . 'setting the GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES environment '
                . 'Variable to 1.'
            );
        }

        if ($this->outputFile && file_exists($this->outputFile)) {
            $outputFileContents = file_get_contents($this->outputFile) ?: '';
            $cachedToken = json_decode($outputFileContents, true);
            if (time() < ($cachedToken['expiration_time'] ?? 0)) {
                return $cachedToken;
            }
        }

        // Run the executable.
        $exitCode = ($this->executableHandler)($this->command);
        $output = $this->executableHandler->getOutput();

        // If the exit code is not 0, throw an exception with the output as the error details
        if ($exitCode !== 0) {
            throw new RuntimeException(
                'The executable failed to run'
                . ($output ? ' with the following error: ' . $output : '.'),
                $exitCode
            );
        }

        return $this->parseTokenFromResponse($output);
    }

    private function parseTokenFromResponse(string $responseJson): string
    {
        $json = json_decode($responseJson, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new UnexpectedValueException('The executable response is not valid JSON.');
        }
        if (empty($json['version'])) {
            throw new UnexpectedValueException('Executable response must contain a "version" field.');
        }
        if (!array_key_exists('success', $json)) {
            throw new UnexpectedValueException('Executable response must contain a "success" field.');
        }

        // Validate required fields for a successful response.
        if ($json['success']) {
            // Validate token type field.
            $tokenTypes = [self::SAML_SUBJECT_TOKEN_TYPE, self::OIDC_SUBJECT_TOKEN_TYPE1, self::OIDC_SUBJECT_TOKEN_TYPE2];
            if (!isset($json['token_type']) || !in_array($json['token_type'], $tokenTypes)) {
                throw new UnexpectedValueException(sprintf(
                    'Executable response must contain a "token_type" field when successful and it'
                    . ' must be one of %s.',
                    implode(', ', $tokenTypes)
                ));
            }

            // Validate subject token.
            if ($json['token_type'] === self::SAML_SUBJECT_TOKEN_TYPE) {
                if (empty($json['saml_response'])) {
                    throw new UnexpectedValueException(sprintf(
                        'Executable response must contain a "saml_response" field when token_type=%s.',
                        self::SAML_SUBJECT_TOKEN_TYPE
                    ));
                }
                return $json['saml_response'];
            }

            if (empty($json['id_token'])) {
                throw new UnexpectedValueException(sprintf(
                    'Executable response must contain a "id_token" field when '
                    . 'token_type=%s.',
                    $json['token_type']
                ));
            }

            return $json['id_token'];
        }

        // Both code and message must be provided for unsuccessful responses.
        if (empty($json['code'])) {
            throw new UnexpectedValueException('Executable response must contain a "code" field when unsuccessful.');
        }
        if (empty($json['message'])) {
            throw new UnexpectedValueException('Executable response must contain a "message" field when unsuccessful.');
        }

        throw new UnexpectedValueException($json['message'], $json['code']);
    }
}
