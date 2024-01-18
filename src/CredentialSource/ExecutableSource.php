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

use Google\Auth\ExternalAccountCredentialSourceInterface;
use InvalidArgumentException;
use UnexpectedValueException;
use RuntimeException;

/**
 * Retrieve a token from an executable.
 *
 * The auth libraries will populate certain environment variables that will be accessible by the
 * executable, such as: GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE, GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE,
 * GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE, GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL, and
 * GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE.
 */
class ExecutableSource implements ExternalAccountCredentialSourceInterface
{
    /**
     * The default executable timeout when none is provided, in milliseconds.
     */
    private const DEFAULT_EXECUTABLE_TIMEOUT_MILLIS = 30 * 1000;
    private const GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES = 'GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES';

    private string $executable;
    private string $audience;
    private string $subjectTokenType;
    private int $timeoutMillis;
    private ?string $outputFile;
    private ?string $serviceAccountEmail;

    /**
     * @param string $executable    The string executable to run to get the subject token.
     * @param string $timeoutMillis
     * @param string $outputFile
     */
    public function __construct(
        string $executable,
        string $audience,
        string $subjectTokenType,
        int $timeoutMillis = null,
        string $outputFile = null,
        string $serviceAccountEmail = null
    ) {
        $this->executable = $executable;
        $this->timeoutMillis = $timeoutMillis ?? self::DEFAULT_EXECUTABLE_TIMEOUT_MILLIS;
        $this->outputFile = $outputFile;
        $this->audience = $audience;
        $this->subjectTokenType = $subjectTokenType;
        $this->serviceAccountEmail = $serviceAccountEmail;
    }

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
        $contents = file_get_contents($this->file);
        if ($this->format === 'json') {
            if (!$json = json_decode((string) $contents, true)) {
                throw new UnexpectedValueException(
                    'Unable to decode JSON file'
                );
            }
            if (!isset($json[$this->subjectTokenFieldName])) {
                throw new UnexpectedValueException(
                    'subject_token_field_name not found in JSON file'
                );
            }
            $contents = $json[$this->subjectTokenFieldName];
        }

        return $contents;
    }

    private function setExecutableEnvironmentVariables()
    {
        putenv('GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE=' . $this->audience);
        putenv('GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE=' . $this->subjectTokenType);
        // Always set to 0 because interactive mode is not supported.
        putenv('GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE=0');
        if ($this->outputFile) {
            putenv('GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE=' . $this->outputFile);
        }
        if ($this->serviceAccountEmail) {
            putenv('GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL=' . $this->serviceAccountEmail);
        }
    }
}
