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
namespace Google\Auth\HttpHandler;

use Google\Auth\ApplicationDefaultCredentials;
use GuzzleHttp\BodySummarizer;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Psr\Log\LoggerInterface;

class HttpHandlerFactory
{
    /**
     * Builds out a default http handler for the installed version of guzzle.
     *
     * @param ClientInterface|null $client
     * @param null|false|LoggerInterface $logger
     * @return Guzzle6HttpHandler|Guzzle7HttpHandler
     * @throws \Exception
     */
    public static function build(
        ?ClientInterface $client = null,
        null|false|LoggerInterface $logger = null,
    ) {
        if (is_null($client)) {
            $config = [];
            if (class_exists(BodySummarizer::class)) {
                // double the # of characters before truncation by default
                $bodySummarizer = new BodySummarizer(240);
                $stack = HandlerStack::create();
                $stack->remove('http_errors');
                $stack->unshift(Middleware::httpErrors($bodySummarizer), 'http_errors');
                $config['handler'] = $stack;
            }
            $client = new Client($config);
        }

        $logger = ($logger === false)
            ? null
            : $logger ?? ApplicationDefaultCredentials::getDefaultLogger();

        switch (ClientInterface::MAJOR_VERSION) {
            case 7:
            case 8:
                return new Guzzle7HttpHandler($client, $logger);
            default:
                throw new \Exception('Version not supported');
        }
    }
}
