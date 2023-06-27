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

use Google\Auth\FetchAuthTokenInterface;
use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Psr7\Request;

/**
 * Retrieve a token from a URL.
 *
 * @internal
 */
class UrlSource implements FetchAuthTokenInterface
{
    private string $url;
    private array $headers;
    private ?string $format;
    private ?string $subjectTokenFieldName;

    public function __construct(
        string $url,
        array $headers = [],
        string $format = null,
        string $subjectTokenFieldName = null
    ) {
        $this->url = $url;
        $this->headers = $headers;

        if ($format === 'json' && is_null($subjectTokenFieldName)) {
            throw new InvalidArgumentException(
                'subject_token_field_name must be set when format is JSON'
            );
        }

        $this->format = $format;
        $this->subjectTokenFieldName = $subjectTokenFieldName;
    }

    public function fetchToken(callable $httpHandler = null): string
    {
        if (is_null($httpHandler)) {
            $httpHandler = HttpHandlerFactory::build(HttpClientCache::getHttpClient());
        }

        $request = new Request(
            $this->url,
            'GET',
            $this->headers
        );

        $response = $httpHandler($request);
        $body = (string) $response->getBody();
        if ($this->format === 'json') {
            $json = json_decode((string) $body, true);
            $body = $json[$this->subjectTokenFieldName];
        }

        return ['access_token' => $body];
    }

    public function getCacheKey()
    {
        return '';
    }

    public function getLastReceivedToken()
    {
        return null;
    }
}
