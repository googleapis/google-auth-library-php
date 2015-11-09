<?php

namespace Google\Auth;

use Http\Discovery\MessageFactoryDiscovery;
use Http\Message\MessageFactory;

class RequestBuilder
{
    /**
     * @var MessageFactory
     */
    static $factory;

    /**
     * @param string $method
     * @param string $uri
     * @param array $headers
     * @param null $body
     * @param string $protocolVersion
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    static function getRequest($method, $uri, array $headers = [], $body = null, $protocolVersion = '1.1') {

        if (self::$factory === null) {
            self::$factory = MessageFactoryDiscovery::find();
        }

        return self::$factory->createRequest($method, $uri, $headers, $body, $protocolVersion);
    }
}