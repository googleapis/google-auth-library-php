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

use Symfony\Component\Process\Process;

class ExecutableHandler
{
    private const DEFAULT_EXECUTABLE_TIMEOUT_MILLIS = 30 * 1000;

    private int $timeoutMs;
    private array $env = [];
    private ?string $output = null;
    private ?string $errorCode = null;
    private ?string $errorMessage = null;

    public function __construct(
        int $timeoutMs = self::DEFAULT_EXECUTABLE_TIMEOUT_MILLIS,
        array $env = []
    ) {
        if (!class_exists(Process::class)) {
            throw new RuntimeException(
                'The "symfony/process" package is required to use the ProcessExecutableHandler.'
            );
        }
        $this->timeoutMs = $timeoutMs;
        $this->env = $env;
    }

    /**
     * @param string $command
     * @return int
     */
    public function __invoke(string $command): int
    {
        $process = Process::fromShellCommandline(
            $command,
            null,
            $this->env,
            null,
            ($this->timeoutMs / 1000)
        );

        $process->run();

        $this->output = $process->getOutput();

        return $process->getExitCode();
    }

    public function getOutput(): ?string
    {
        return $this->output;
    }
}
