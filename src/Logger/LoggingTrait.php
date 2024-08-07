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

namespace Google\Auth\Logger;

use Google\ApiCore\Call;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

trait LoggingTrait
{
     /**
     * @param LogEvent
     *
     * @return string
     */
    private function logRequest(LogEvent $event): void
    {
        $timestamp = $event->timestamp;

        $debugEvent = [
            'timestamp' => $timestamp,
            'severity' => 'DEBUG', //Perhaps have something like Logger::debug
        ];

        $jsonPayload = [
            'request.method' => $event->method,
            'request.url' => $event->url,
            'request.headers' => $event->headers,
            'request.payload' => $event->payload,
            'request.rpcName' => $event->rpcName,
            'jwt' => $this->getJwtToken($event->headers),
            'retryAttempt' => $event->retryAttempt
        ];

        // Filters out all the falsey values
        $jsonPayload = array_filter($jsonPayload);

        $this->logger->debug((string)json_encode($debugEvent));
    }

    /**
     * @param LogEvent $response
     *
     * @return void
     */
    private function logResponse(LogEvent $event): void
    {
        $debugEvent = [
            'timestamp' => $event->timestamp,
            'severity' => 'DEBUG', //Perhaps have something like Logger::debug
            'jsonPayload' => [
                'response.headers' => $event->headers,
                'response.payload' => $event->payload,
                'latency' => $event->latency,
            ]
        ];

        $this->logger->debug((string)json_encode($debugEvent));

        $infoEvent = [
            'timestamp' => $event->timestamp,
            'severity' => 'INFO', //Perhaps have something like Logger::debug
            'jsonPayload' => [
                'response.status' => $event->status
            ]
        ];

        $this->logger->info((string)json_encode($infoEvent));
    }

    /**
     * @param array $headers
     * @return null|array
     */
    private function getJwtToken(array $headers): null|array
    {
        $tokenHeader = $headers['Authorization'] ?? '';
        $token = str_replace('Bearer ', '', $tokenHeader);

        if (substr_count($token, '.') !== 2) {
            return null;
        }

        [$header, $token, $_] = explode('.', $token);

        return [
            'jwt' => [
                'header' => base64_decode($header),
                'token' => base64_decode($token)
            ]
        ];
    }
}