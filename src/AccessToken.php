<?php
/*
 * Copyright 2019 Google LLC
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

namespace Google\Auth;

use DateTime;
use DomainException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Psr\Cache\CacheItemPoolInterface;
use RuntimeException;
use stdClass;
use UnexpectedValueException;

/**
 * Wrapper around Google Access Tokens which provides convenience functions.
 *
 * @experimental
 */
class AccessToken
{
    const FEDERATED_SIGNON_CERT_URL = 'https://www.googleapis.com/oauth2/v3/certs';
    const IAP_CERT_URL = 'https://www.gstatic.com/iap/verify/public_key-jwk';
    const IAP_ISSUER = 'https://cloud.google.com/iap';
    const OAUTH2_ISSUER = 'accounts.google.com';
    const OAUTH2_ISSUER_HTTPS = 'https://accounts.google.com';
    const OAUTH2_REVOKE_URI = 'https://oauth2.googleapis.com/revoke';

    /**
     * @var callable
     */
    private $httpHandler;

    /**
     * @var CacheItemPoolInterface
     */
    private $cache;

    private JWT $jwt;

    /**
     * @param callable $httpHandler [optional] An HTTP Handler to deliver PSR-7 requests.
     * @param CacheItemPoolInterface $cache [optional] A PSR-6 compatible cache implementation.
     */
    public function __construct(
        callable $httpHandler = null,
        CacheItemPoolInterface $cache = null,
        JWT $jwt = null
    ) {
        $this->httpHandler = $httpHandler
            ?: HttpHandlerFactory::build(HttpClientCache::getHttpClient());
        $this->cache = $cache ?: new MemoryCacheItemPool();
        $this->jwt = $jwt ?: new JWT();
    }

    /**
     * Verifies an id token and returns the authenticated apiLoginTicket.
     * Throws an exception if the id token is not valid.
     * The audience parameter can be used to control which id tokens are
     * accepted.  By default, the id token must have been issued to this OAuth2 client.
     *
     * @param string $token The JSON Web Token to be verified.
     * @param array<mixed> $options [optional] {
     *     Configuration options.
     *     @type string $audience The indended recipient of the token.
     *     @type string $issuer The intended issuer of the token.
     *     @type string $cacheKey The cache key of the cached certs. Defaults to
     *        the sha1 of $certsLocation if provided, otherwise is set to
     *        "federated_signon_certs_v3".
     *     @type string $certsLocation The location (remote or local) from which
     *        to retrieve certificates, if not cached. This value should only be
     *        provided in limited circumstances in which you are sure of the
     *        behavior.
     *     @type bool $throwException Whether the function should throw an
     *        exception if the verification fails. This is useful for
     *        determining the reason verification failed.
     * }
     * @return array<mixed>|false the token payload, if successful, or false if not.
     * @throws InvalidArgumentException If certs could not be retrieved from a local file.
     * @throws InvalidArgumentException If received certs are in an invalid format.
     * @throws InvalidArgumentException If the cert alg is not supported.
     * @throws RuntimeException If certs could not be retrieved from a remote location.
     * @throws UnexpectedValueException If the token issuer does not match.
     * @throws UnexpectedValueException If the token audience does not match.
     */
    public function verify($token, array $options = [])
    {
        $audience = $options['audience'] ?? null;
        $issuer = $options['issuer'] ?? null;
        $certsLocation = $options['certsLocation'] ?? self::FEDERATED_SIGNON_CERT_URL;
        $cacheKey = $options['cacheKey'] ?? $this->getCacheKeyFromCertLocation($certsLocation);
        $throwException = $options['throwException'] ?? false; // for backwards compatibility

        // Check signature against each available cert.
        $certs = $this->getCerts($certsLocation, $cacheKey, $options);
        try {
            $keys = [];
            foreach ($certs as $cert) {
                if (empty($cert['kid'])) {
                    throw new InvalidArgumentException('certs expects "kid" to be set');
                }
                // create an array of key IDs to certs for the JWT library
                $keys[(string) $cert['kid']] = JWK::parseKey($cert);
            }
            $headers = new stdClass();
            $payload = ($this->jwt)::decode($token, $keys, $headers);

            if ($audience) {
                if (!property_exists($payload, 'aud') || $payload->aud != $audience) {
                    throw new UnexpectedValueException('Audience does not match');
                }
            }

            // support HTTP and HTTPS issuers
            // @see https://developers.google.com/identity/sign-in/web/backend-auth
            if (is_null($issuer)) {
                $issuers = $headers->alg == 'RS256'
                    ?  [self::OAUTH2_ISSUER, self::OAUTH2_ISSUER_HTTPS] // default to OAuth2 for RS256
                    :  [self::IAP_ISSUER]; // default to IAP for ES256
            } else {
                $issuers = [$issuer];
            }
            if (!isset($payload->iss) || !in_array($payload->iss, $issuers)) {
                throw new UnexpectedValueException('Issuer does not match');
            }

            return (array) $payload;

        } catch (ExpiredException $e) {
        } catch (SignatureInvalidException $e) {
        } catch (InvalidArgumentException $e) {
        } catch (UnexpectedValueException $e) {
        } catch (DomainException $e) {
        }

        if ($throwException) {
            throw $e;
        }

        return false;
    }

    /**
     * Revoke an OAuth2 access token or refresh token. This method will revoke the current access
     * token, if a token isn't provided.
     *
     * @param string|array<mixed> $token The token (access token or a refresh token) that should be revoked.
     * @param array<mixed> $options [optional] Configuration options.
     * @return bool Returns True if the revocation was successful, otherwise False.
     */
    public function revoke($token, array $options = [])
    {
        if (is_array($token)) {
            if (isset($token['refresh_token'])) {
                $token = $token['refresh_token'];
            } else {
                $token = $token['access_token'];
            }
        }

        $body = Utils::streamFor(http_build_query(['token' => $token]));
        $request = new Request('POST', self::OAUTH2_REVOKE_URI, [
            'Cache-Control' => 'no-store',
            'Content-Type'  => 'application/x-www-form-urlencoded',
        ], $body);

        $httpHandler = $this->httpHandler;

        $response = $httpHandler($request, $options);

        return $response->getStatusCode() == 200;
    }

    /**
     * Gets federated sign-on certificates to use for verifying identity tokens.
     * Returns certs as array structure, where keys are key ids, and values
     * are PEM encoded certificates.
     *
     * @param string $location The location from which to retrieve certs.
     * @param string $cacheKey The key under which to cache the retrieved certs.
     * @param array<mixed> $options [optional] Configuration options.
     * @return array<mixed>
     * @throws InvalidArgumentException If received certs are in an invalid format.
     */
    private function getCerts($location, $cacheKey, array $options = [])
    {
        $cacheItem = $this->cache->getItem($cacheKey);
        $certs = $cacheItem ? $cacheItem->get() : null;

        $expireTime = null;
        if (!$certs) {
            list($certs, $expireTime) = $this->retrieveCertsFromLocation($location, $options);
        }

        if (!isset($certs['keys'])) {
            if ($location !== self::IAP_CERT_URL) {
                throw new InvalidArgumentException(
                    'federated sign-on certs expects "keys" to be set'
                );
            }
            throw new InvalidArgumentException(
                'certs expects "keys" to be set'
            );
        }

        // Push caching off until after verifying certs are in a valid format.
        // Don't want to cache bad data.
        if ($expireTime) {
            $cacheItem->expiresAt(new DateTime($expireTime));
            $cacheItem->set($certs);
            $this->cache->save($cacheItem);
        }

        return $certs['keys'];
    }

    /**
     * Retrieve and cache a certificates file.
     *
     * @param string $url location
     * @param array<mixed> $options [optional] Configuration options.
     * @return array{array<mixed>, string}
     * @throws InvalidArgumentException If certs could not be retrieved from a local file.
     * @throws RuntimeException If certs could not be retrieved from a remote location.
     */
    private function retrieveCertsFromLocation($url, array $options = [])
    {
        // If we're retrieving a local file, just grab it.
        $expireTime = '+1 hour';
        if (strpos($url, 'http') !== 0) {
            if (!file_exists($url)) {
                throw new InvalidArgumentException(sprintf(
                    'Failed to retrieve verification certificates from path: %s.',
                    $url
                ));
            }

            return [
                json_decode((string) file_get_contents($url), true),
                $expireTime
            ];
        }

        $httpHandler = $this->httpHandler;
        $response = $httpHandler(new Request('GET', $url), $options);

        if ($response->getStatusCode() == 200) {
            if ($cacheControl = $response->getHeaderLine('Cache-Control')) {
                array_map(function ($value) use (&$expireTime) {
                    list($key, $value) = explode('=', $value) + [null, null];
                    if (trim($key) == 'max-age') {
                        $expireTime = '+' . $value . ' seconds';
                    }
                }, explode(',', $cacheControl));
            }
            return [
                json_decode((string) $response->getBody(), true),
                $expireTime
            ];
        }

        throw new RuntimeException(sprintf(
            'Failed to retrieve verification certificates: "%s".',
            $response->getBody()->getContents()
        ), $response->getStatusCode());
    }

    /**
     * Generate a cache key based on the cert location using sha1 with the
     * exception of using "federated_signon_certs_v3" to preserve BC.
     *
     * @param string $certsLocation
     * @return string
     */
    private function getCacheKeyFromCertLocation($certsLocation)
    {
        $key = $certsLocation === self::FEDERATED_SIGNON_CERT_URL
            ? 'federated_signon_certs_v3'
            : sha1($certsLocation);

        return 'google_auth_certs_cache|' . $key;
    }
}
