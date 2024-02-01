<?php
/**
 * Copyright 2015 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace Google\Auth\ExecutableHandler;

class ExecutableHandler
{
    private const DEFAULT_EXECUTABLE_TIMEOUT_MILLIS = 30 * 1000;

    private int $timeout;
    private array $envVars;

    public function __construct(
        int $timeout = self::DEFAULT_EXECUTABLE_TIMEOUT_MILLIS,
        array $envVars = []
    ) {
        $this->timeout = $timeout;
        $this->envVars = $envVars;
    }

    /**
     * @param string $command
     * @param int|null $returnVar
     */
    public function __invoke(string $command, ?int &$returnVar): string
    {
        $envVarString = implode(' ', array_map(
            fn ($key, $value) => "$key=$value",
            array_keys($this->envVars),
            $this->envVars
        ));
        $command = escapeshellcmd($envVarString . ' ' . $command);
        exec($command, $output, $returnVar);

        return implode("\n", $output);
    }
}
