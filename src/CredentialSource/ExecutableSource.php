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
    private int $timeoutMillis;
    private ?string $outputFile;
    private array $environmentVariables;

    /**
     * @param string $executable    The string executable to run to get the subject token.
     * @param string $timeoutMillis
     * @param string $outputFile
     */
    public function __construct(
        string $executable,
        ?int $timeoutMillis,
        ?string $outputFile,
        array $environmentVariables = [],
    ) {
        $this->executable = $executable;
        $this->timeoutMillis = $timeoutMillis ?: self::DEFAULT_EXECUTABLE_TIMEOUT_MILLIS;
        $this->outputFile = $outputFile;
        $this->environmentVariables = $environmentVariables;
    }

    /**
     * @param callable $executableHandler   A function which returns the output of the command with
     *                                      the following function signature:
     *                                      function (string $command, array $envVars, int &$returnVar): string
     */
    public function fetchSubjectToken(callable $httpHandler = null, callable $executableHandler = null): string
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
            $cachedToken = json_decode(file_get_contents($this->outputFile), true);
            if (time() < ($cachedToken['expiration_time'] ?? 0)) {
                return $cachedToken;
            }
        }

        $executableHandler ??= function (string $command, array $envVars, &$returnVar): string {
            $envVarString = implode(' ', array_map(
                fn ($key, $value) => "$key=$value",
                array_keys($envVars),
                $envVars
            ));
            $command = escapeshellcmd($envVarString . ' ' . $command);
            exec($command, $output, $returnVar);

            return implode("\n", $output);
        };

        // Run the executable.
        $returnVar = null;
        $cmdOutput = $executableHandler($this->executable, $this->environmentVariables, $returnVar);

        // If the exit code is not 0, throw an exception with the output as the error details
        if ($returnVar !== 0) {
            throw new RuntimeException(
                'The executable failed to run'
                . ($cmdOutput ? ' with the following error: ' . $cmdOutput : '.')
            );
        }

        // If the exit code is 0 and there's a response, return the output as the subject token.
        if ($cmdOutput) {
            $json = json_decode($cmdOutput, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return $json['id_token'];
            }
        }

        if ($this->outputFile && $fileContents = file_get_contents($this->outputFile)) {
            json_decode($fileContents);
            if (json_last_error() === JSON_ERROR_NONE) {
                return $string;
            }
            return $fileContents;
        }

        throw new RuntimeException('Unable to retrieve a token from the executable.');
    }
}
