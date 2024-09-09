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

use Psr\Log\LogLevel;

trait LoggingTrait
{
    private function logRequest(LogEvent $event): void
    {
        $debugEvent = [
            'timestamp' => $event->timestamp,
            'severity' => strtoupper(LogLevel::DEBUG),
            'clientId' => $event->clientId,
            'requestId' => $event->requestId,
        ];

        $jsonPayload = [
            'request.method' => $event->method,
            'request.url' => $event->url,
            'request.headers' => $event->headers,
            'request.payload' => $event->payload,
            'request.jwt' => $this->getJwtToken($event->headers),
            'retryAttempt' => $event->retryAttempt
        ];

        // Filter out the falsey values
        $jsonPayload = array_filter($jsonPayload);
        $debugEvent['jsonPayload'] = $jsonPayload;

        $this->logger->debug((string) json_encode($debugEvent));
    }

    private function logResponse(LogEvent $event): void
    {
        $debugEvent = [
            'timestamp' => $event->timestamp,
            'severity' => strtoupper(LogLevel::DEBUG),
            'clientId' => $event->clientId,
            'requestId' => $event->requestId,
            'jsonPayload' => [
                'response.headers' => $event->headers,
                'response.payload' => $event->payload,
                'latency' => $event->latency,
            ]
        ];

        $this->logger->debug((string) json_encode($debugEvent));

        $infoEvent = [
            'timestamp' => $event->timestamp,
            'severity' => LogLevel::INFO,
            'clientId' => $event->clientId,
            'requestId' => $event->requestId,
            'jsonPayload' => [
                'response.status' => $event->status
            ]
        ];

        $this->logger->info((string) json_encode($infoEvent));
    }

    private function getJwtToken(array $headers): null|array
    {
        $tokenHeader = $headers['Authorization'] ?? '';
        $token = str_replace('Bearer ', '', $tokenHeader);

        if (substr_count($token, '.') !== 2) {
            return null;
        }

        [$header, $token, $_] = explode('.', $token);

        return [
            'header' => base64_decode($header),
            'token' => base64_decode($token)
        ];
    }
}