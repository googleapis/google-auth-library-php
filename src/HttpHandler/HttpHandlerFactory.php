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

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;

class HttpHandlerFactory
{
    /**
     * Save the HttpHandler to prevent many instances being created.
     *
     * @var callable
     */
    private static $httpHandler;

    /**
     * Builds out a default http handler for the installed version of guzzle.
     *
     * If a handler has been previously created, it will be returned instead
     * of a new handler being created.
     *
     * @param ClientInterface $client
     *
     * @return Guzzle5HttpHandler|Guzzle6HttpHandler
     *
     * @throws \Exception
     */
    public static function build(ClientInterface $client = null)
    {
        if (self::$httpHandler) {
            return self::$httpHandler;
        }

        $version = ClientInterface::VERSION;
        $client = $client ?: new Client();

        switch ($version[0]) {
            case '5':
                self::$httpHandler = new Guzzle5HttpHandler($client);
                break;
            case '6':
                self::$httpHandler = new Guzzle6HttpHandler($client);
                break;
            default:
                throw new \Exception(sprintf('Version %s not supported', $version));
        }

        return self::$httpHandler;
    }

    /**
     * Modify the saved handler.
     *
     * @param callable $httpHandler If null, the saved handler will be dropped.
     * @return void
     */
    public static function setHandler(callable $httpHandler = null)
    {
        self::$httpHandler = $httpHandler;
    }
}
