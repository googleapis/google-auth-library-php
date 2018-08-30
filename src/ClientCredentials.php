<?php
/*
 * Copyright 2018, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
namespace Google\ApiCore;

use DomainException;
use Exception;
use Google\Auth\ApplicationDefaultCredentials;
use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Auth\CredentialsLoader;
use Google\Auth\FetchAuthTokenCache;
use Google\Auth\FetchAuthTokenInterface;
use Google\Auth\HttpHandler\Guzzle5HttpHandler;
use Google\Auth\HttpHandler\Guzzle6HttpHandler;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use Psr\Cache\CacheItemPoolInterface;

/**
 * The ClientCredentials object provides a wrapper around a FetchAuthTokenInterface.
 */
class ClientCredentials
{
    private $credentialsFetcher;
    private $authHttpHandler;

    /**
     * @param FetchAuthTokenInterface $credentialsFetcher A credentials loader
     *        used to fetch access tokens.
     * @param callable $authHttpHandler A handler used to deliver PSR-7 requests
     *        specifically for authentication. Should match a signature of
     *        `function (RequestInterface $request, array $options) : ResponseInterface`.
     * @throws Exception
     */
    public function __construct(FetchAuthTokenInterface $credentialsFetcher, callable $authHttpHandler = null)
    {
        $this->credentialsFetcher = $credentialsFetcher;
        $this->authHttpHandler = $authHttpHandler ?: self::buildHttpHandlerFactory();
    }

    /**
     * @param array $args {
     *     An array of optional arguments.
     *
     *     @type string[] $scopes
     *           A string array of scopes to use when acquiring credentials.
     *     @type callable $authHttpHandler
     *           A handler used to deliver PSR-7 requests specifically
     *           for authentication. Should match a signature of
     *           `function (RequestInterface $request, array $options) : ResponseInterface`.
     *     @type bool $enableCaching
     *           Enable caching of access tokens. Defaults to true.
     *     @type CacheItemPoolInterface $authCache
     *           A cache for storing access tokens. Defaults to a simple in memory implementation.
     *     @type array $authCacheOptions
     *           Cache configuration options.
     * }
     * @return ClientCredentials
     * @throws DomainException
     * @throws Exception
     */
    public static function build(array $args = [])
    {
        $args += [
            'scopes'            => null,
            'authHttpHandler'   => null,
            'enableCaching'     => true,
            'authCache'         => null,
            'authCacheOptions'  => null,
        ];
        $authHttpHandler = $args['authHttpHandler'] ?: self::buildHttpHandlerFactory();
        $authCacheOptions = $args['authCacheOptions'];
        if ($args['enableCaching']) {
            $authCache = $args['authCache'] ?: new MemoryCacheItemPool();
        } else {
            $authCache = null;
        }

        $credentialsLoader = self::buildApplicationDefaultCredentials(
            $args['scopes'],
            $authHttpHandler,
            $authCacheOptions,
            $authCache
        );

        return new ClientCredentials($credentialsLoader, $authHttpHandler);
    }

    /**
     * Factory method to create an AuthWrapper from an authConfig array.
     *
     * @param string|array $keyFile
     *     Credentials to be used. Accepts either a path to a credentials file, or a decoded
     *     credentials file as a PHP array.
     * @param array $authConfig {
     *     @type string[] $scopes The scopes required by this AuthWrapper.
     *     @type callable $authHttpHandler
     *           Optional. A handler used to deliver PSR-7 requests specifically
     *           for authentication. Should match a signature of
     *           `function (RequestInterface $request, array $options) : ResponseInterface`.
     *     @type bool $enableCaching
     *           Optional. Enable caching of access tokens. Defaults to true.
     *     @type CacheItemPoolInterface $authCache
     *           Optional. A cache for storing access tokens. Defaults to a simple in memory implementation.
     * }
     * @return ClientCredentials
     * @throws Exception
     */
    public static function fromKeyFile($keyFile, array $authConfig)
    {
        $authConfig += [
            'scopes'            => null,
            'enableCaching'     => true,
            'authCache'         => null,
            'authCacheOptions'  => [],
            'authHttpHandler'   => null,
        ];

        $loader = CredentialsLoader::makeCredentials($authConfig['scopes'], $keyFile);

        if ($authConfig['enableCaching']) {
            $authCache = $authConfig['authCache'] ?: new MemoryCacheItemPool();
            $loader = new FetchAuthTokenCache(
                $loader,
                $authConfig['authCacheOptions'],
                $authCache
            );
        }

        return new ClientCredentials($loader, $authConfig['authHttpHandler']);
    }

    /**
     * @return string Access token.
     */
    public function getAccessToken()
    {
        return self::getToken($this->credentialsFetcher, $this->authHttpHandler);
    }

    /**
     * @return string Bearer string containing access token.
     */
    public function getBearerString()
    {
        return 'Bearer ' . self::getToken($this->credentialsFetcher, $this->authHttpHandler);
    }

    /**
     * @return callable Callable function that returns an authorization header.
     */
    public function getAuthorizationHeaderCallback()
    {
        $fetchAuthTokenInterface = $this->credentialsFetcher;
        $authHttpHandler = $this->authHttpHandler;

        // NOTE: changes to this function should be treated carefully and tested thoroughly. It will
        // be passed into the gRPC c extension, and changes have the potential to trigger very
        // difficult-to-diagnose segmentation faults.
        return function () use ($fetchAuthTokenInterface, $authHttpHandler) {
            return ['authorization' => ['Bearer ' . self::getToken($fetchAuthTokenInterface, $authHttpHandler)]];
        };
    }

    /**
     * @return Guzzle5HttpHandler|Guzzle6HttpHandler
     * @throws Exception
     */
    private static function buildHttpHandlerFactory()
    {
        return HttpHandlerFactory::build();
    }

    /**
     * @param array $scopes
     * @param callable $authHttpHandler
     * @param array $authCacheOptions
     * @param CacheItemPoolInterface $authCache
     * @return CredentialsLoader
     * @throws DomainException
     */
    private static function buildApplicationDefaultCredentials(
        array $scopes = null,
        callable $authHttpHandler = null,
        array $authCacheOptions = null,
        CacheItemPoolInterface $authCache = null
    ) {
        return ApplicationDefaultCredentials::getCredentials(
            $scopes,
            $authHttpHandler,
            $authCacheOptions,
            $authCache
        );
    }

    private static function getToken($credentialsFetcher, $authHttpHandler)
    {
        $token = $credentialsFetcher->getLastReceivedToken();
        if (self::isExpired($token)) {
            $token = $credentialsFetcher->fetchAuthToken($authHttpHandler);
            if (!self::isValid($token)) {
                return '';
            }
        }
        return $token['access_token'];
    }

    private static function isValid($token)
    {
        return is_array($token)
            && array_key_exists('access_token', $token);
    }

    private static function isExpired($token)
    {
        return !(self::isValid($token)
            && array_key_exists('expires_at', $token)
            && $token['expires_at'] > time());
    }
}
