<?php
/*
 * Copyright 2019 Google LLC.
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

namespace Google\Auth;

/**
 * An interface implemented by objects that can fetch ID tokens.
 */
interface FetchIdTokenInterface
{
    /**
     * Fetches an ID token based on the current state.
     *
     * @param callable $httpHandler callback which delivers psr7 request
     *
     * @return string ID token
     */
    public function fetchIdToken(callable $httpHandler = null);
}
