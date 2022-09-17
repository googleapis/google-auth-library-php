<?php
/**
 * Copyright 2022 Google Inc. All Rights Reserved.
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
namespace Google\Auth\HttpHandler;

use GuzzleHttp\MessageFormatter;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class RequestResponseDebugFormatter extends MessageFormatter
{
    /**
     * Request/Response level debugging middleware. Logs:
     * - Request method.
     * - Request URI.
     * - Response status.
     * - Truncated Authoriztion header.
     * - X-Google-Project-Id header.
     * - Error raised (if applicable).
     * 
     * @param RequestInterface Guzzle request.
     * @param RequestInterface Guzzle response.
     * @param \Exception error.
     * @return string JSON encoded log line.
     */
    public function format(
        RequestInterface $request,
        ResponseInterface $response = null,
        \Exception $error = null
    ) {
        $message = sprintf('%s %s', $request->getMethod(), (string) $request->getUri());

        if (!is_null($response)) {
            $message = sprintf('[%d] %s', $response->getStatusCode(), $message);
        } elseif (! is_null($error)) {
            $message = $error->getMessage();
        }

        return json_encode([
            'message' => $message,
            'request' => $this->request($request),
            'response' => $this->response($response),
            'error' => $this->error($error),
        ]);
    }

    /**
     * Format the request data.
     *
     * @param  \Psr\Http\Message\RequestInterface $request
     * @return array
     */
    protected function request(RequestInterface $request)
    {
        $data = [
            'target' => $request->getRequestTarget(),
            'method' => $request->getMethod(),
            'uri' => (string) $request->getUri(),
            'headers' => $this->headers($request->getHeaders()),
        ];
        return $data;
    }

    /**
     * Format the response data.
     *
     * @param  \Psr\Http\Message\ResponseInterface|null $response
     * @return array
     */
    protected function response(ResponseInterface $response = null)
    {
        if (is_null($response)) {
            return [];
        }

        return [
            'status' => $response->getStatusCode(),
            'headers' => $this->headers($response->getHeaders()),
        ];
    }

    /**
     * Format the exception message.
     *
     * @param  \Exception $exception
     * @return array
     */
    protected function error(\Exception $exception = null)
    {
        if (is_null($exception)) {
            return [];
        }

        return [
            'message' => $exception->getMessage(),
            'code' => $exception->getCode(),
        ];
    }

    /**
     * Format the given headers.
     *
     * @param  array  $headers
     * @return array
     */
    protected function headers($headers)
    {
        $headers = array_map(function ($header) {
            return $header[0] ?? [];
        }, $headers);
        $h = [];
        # Truncate auth token to 36 bytes, which is identifiable but
        # does not leak key in logs:
        $safe_auth_header_length = strlen('Bearer ') + 36;
        if (isset($headers['Authorization'])) {
          $h['Authorization'] = sprintf(
            '%s%s',
            substr($headers['Authorization'], 0, $safe_auth_header_length),
            '*****'
          );
        }
        if (isset($headers['X-Goog-User-Project'])) {
          $h['X-Goog-User-Project'] = $headers['X-Goog-User-Project'];
        }
        return $h;
    }
}
