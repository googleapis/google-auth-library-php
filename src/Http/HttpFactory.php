<?php

/*
 * Copyright 2015 Google Inc.
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

namespace Google\Auth\Http;

use Http\Client\Plugin\Plugin;
use Http\Client\Plugin\PluginClient;
use Http\Discovery\HttpClientDiscovery;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Discovery\StreamFactoryDiscovery;
use Http\Discovery\UriFactoryDiscovery;
use Psr\Http\Message\StreamInterface;

/**
 * A factory to get clients and requests.
 *
 * @author Tobias Nyholm <tobias.nyholm@gmail.com>
 */
class HttpFactory
{
    /**
     * @param array $plugins
     *
     * @return \Http\Client\HttpClient
     */
    public static function getClient($plugins = null)
    {
        if ($plugins === null) {
            return HttpClientDiscovery::find();
        }

        if ($plugins instanceof Plugin) {
            $plugins = [$plugins];
        }

        if (is_array($plugins)) {
            return new PluginClient(HttpClientDiscovery::find(), $plugins);
        }

        throw new \LogicException(
            sprintf(
                'First argument of HttpFactory::getClient must be null, Http\Client\Plugin\Plugin or an array of Http\Client\Plugin\Plugin. You gave a "%s"',
                gettype($plugins)
            )
        );
    }

    /**
     * @param string $method
     * @param string $uri
     * @param array $headers
     * @param null $body
     * @param string $protocolVersion
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    public static function getRequest($method, $uri, array $headers = [], $body = null, $protocolVersion = '1.1')
    {
        return MessageFactoryDiscovery::find()->createRequest($method, $uri, $headers, $body, $protocolVersion);
    }


    /**
     * Creates a new PSR-7 stream.
     *
     * @param string|resource|StreamInterface|null $body
     *
     * @return StreamInterface
     *
     * @throws \InvalidArgumentException If the stream body is invalid.
     */
    public static function getStream($body)
    {
        return StreamFactoryDiscovery::find()->createStream($body);
    }

    public static function getUri($uri)
    {
        return UriFactoryDiscovery::find()->createUri($uri);
    }
}
