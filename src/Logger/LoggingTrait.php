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

use Google\ApiCore\Call;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

trait LoggingTrait
{
     /**
     * @param RequestInterface $request
     *
     * @return string
     */
    private function logHTTPRequest(RequestInterface $request, int $retryAttempt = 0): string
    {
        $timestamp = date(DATE_RFC3339);

        $debugEvent = [
            'timestamp' => $timestamp,
            'severity' => 'DEBUG', //Perhaps have something like Logger::debug
            'jsonPayload' => [
                'request.method' => $request->getMethod(),
                'request.url' => $request->getUri(),
                'request.headers' => $request->getHeaders(),
                'request.payload' => $request->getBody()
            ]
        ];

        $jwtToken = $this->getJwtToken($request->getHeaders());

        if ($jwtToken) {
            $debugEvent['jsonPayload']['JWT'] = $jwtToken;
        }

        if ($retryAttempt) {
            $debugEvent['jsonPayload']['retryAttempt'] = $retryAttempt;
        }

        $this->logger->debug(json_encode($debugEvent));

        return $timestamp;
    }

    /**
     * @param ResponseInterface $response
     *
     * @return void
     */
    private function logHTTPResponse(ResponseInterface $response, string $startTime): void
    {
        $timestamp = date(DATE_RFC3339);
        $latency = strtotime($timestamp) - strtotime($startTime);

        $debugEvent = [
            'timestamp' => $timestamp,
            'severity' => 'DEBUG', //Perhaps have something like Logger::debug
            'jsonPayload' => [
                'response.headers' => $response->getHeaders(),
                'response.payload' => $response->getBody(),
                'latency' => $latency,
            ]
        ];

        $this->logger->debug(json_encode($debugEvent));

        $infoEvent = [
            'timestamp' => $timestamp,
            'severity' => 'INFO', //Perhaps have something like Logger::debug
            'jsonPayload' => [
                'response.status' => $response->getStatusCode()
            ]
        ];

        $this->logger->info(json_encode($infoEvent));
    }

    /**
     * Logs a GRPC call request
     * 
     * @param Call $call
     * @param array $headers
     *
     * @return string
     */
    private function logGRPCRequest(Call $call, array $headers, int $retryAttempt = 0): string
    {
        $timestamp = date(DATE_RFC3339);

        $debugEvent = [
            'timestamp' => $timestamp,
            'severity' => 'DEBUG',
            'jsonPayload' => [
                'request.rpcName' => $call->getMethod(),
                'request.headers' => $headers,
                'request.payload' => $call->getMessage()
            ]
        ];

        $jwtToken = $this->getJwtToken($headers);

        if ($jwtToken) {
            $debugEvent['jsonPayload']['JWT'] = $jwtToken;
        }

        if ($retryAttempt) {
            $debugEvent['jsonPayload']['retryAttempt'] = $retryAttempt;
        }

        $this->logger->debug(json_encode($debugEvent));

        return $timestamp;
    }

    /**
     * @param mixed $response
     * @param mixed $status
     *
     * @return void
     */
    private function logGRPCResponse(mixed $response, mixed $status, string $startTime): void
    {
        $timestamp = date(DATE_RFC3339);
        $latency = strtotime($timestamp) - strtotime($startTime);

        // In the case we have a $status->code != Code::OK
        // from the request, we log the status only and we do not have
        // a response.
        if ($response) {
            $debugEvent = [
                'timestamp' => $timestamp,
                'severity' => 'DEBUG',
                'jsonPayload' => [
                    'response.headers' => $status->metadata,
                    'response.payload' => $response,
                    'latency' => $latency
                ]
            ];

            $this->logger->debug(json_encode($debugEvent));
        }

        $infoEvent = [
            'timestamp' => $timestamp,
            'severity' => 'INFO',
            'jsonPayload' => [
                'response.status' => $status->code
            ]
        ];

        $this->logger->info(json_encode($infoEvent));
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