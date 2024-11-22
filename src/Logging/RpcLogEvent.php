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

namespace Google\Auth\Logging;

class RpcLogEvent
{
    /**
     * Timestamp in format RFC3339 representing when this event ocurred
     *
     * @var string
     */
    public readonly string $timestamp;

    /**
     * The time in milliseconds at time on creation for calculating latency
     *
     * @var float
     */
    public readonly float $milliseconds;

    /**
     * Rest method type
     *
     * @var null|string
     */
    public null|string $method = null;

    /**
     * URL representing the rest URL endpoint
     *
     * @var null|string
     */
    public null|string $url = null;

    /**
     * An array that contains the headers for the response or request
     *
     * @var null|array<mixed>
     */
    public null|array $headers = null;

    /**
     * An array representation of JSON for the response or request
     *
     * @var null|string|array<string, mixed>
     */
    public null|string|array $payload = null;

    /**
     * Status code for REST or gRPC methods
     *
     * @var null|int|string
     */
    public null|int|string $status = null;

    /**
     * The latency in miliseconds
     *
     * @var null|int
     */
    public null|int $latency = null;

    /**
     * The retry attempt number
     *
     * @var null|int
     */
    public null|int $retryAttempt = null;

    /**
     * The name of the gRPC method being called
     *
     * @var null|string
     */
    public null|string $rpcName = null;

    /**
     * The Service Name of the gRPC
     *
     * @var null|string $serviceName
     */
    public null|string $serviceName = null;

    /**
     * The Client Id for tracing
     *
     * @var null|int $clientId
     */
    public null|int $clientId = null;

    /**
     * The Request id for tracing
     *
     * @var null|int $requestId;
     */
    public null|int $requestId = null;

    /**
     * Creates an object with all the fields required for logging
     * Passing a string representation of a timestamp calculates the difference between
     * these two times and sets the latency field with the result.
     *
     * @param null|string $startTime (Optional) Parameter to calculate the latency
     */
    public function __construct(null|float $startTime = null)
    {
        $this->timestamp = date(DATE_RFC3339);

        // Takes the micro time and convets it to millis
        $this->milliseconds = round(microtime(true) * 1000);

        if ($startTime) {
            $this->latency = (int) $this->milliseconds - $startTime;
        }
    }
}
