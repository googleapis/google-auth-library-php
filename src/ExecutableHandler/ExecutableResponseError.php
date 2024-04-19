<?php
/**
 * Copyright 2024 Google Inc. All Rights Reserved.
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

use Error;

class ExecutableResponseError extends Error
{
    private mixed $executableErrorCode;

    public function __construct(string $message, string $executableErrorCode = 'INVALID_EXECUTABLE_RESPONSE')
    {
        $this->executableErrorCode = $executableErrorCode;
        parent::__construct($message);
    }

    public function getExecutableErrorCode(): string
    {
        return $this->executableErrorCode;
    }

    public function __toString(): string
    {
        $msg = parent::__toString();
        return sprintf('Error code %s: %s', $this->executableErrorCode, $msg);
    }
}
