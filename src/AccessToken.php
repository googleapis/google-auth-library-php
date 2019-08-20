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

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Request;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Wrapper around Google Access Tokens which provides convenience functions
 */
class AccessToken
{
    const FEDERATED_SIGNON_CERT_URL = 'https://www.googleapis.com/oauth2/v3/certs';
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

    /**
     * @param callable $httpHandler [optional] An HTTP Handler to deliver PSR-7 requests.
     * @param CacheItemPoolInterface $cache [optional] A PSR-6 compatible cache implementation.
     */
    public function __construct(
        callable $httpHandler = null,
        CacheItemPoolInterface $cache = null
    ) {
        $this->httpHandler = $httpHandler
            ?: HttpHandlerFactory::build(HttpClientCache::getHttpClient());
        $this->cache = $cache ?: new MemoryCacheItemPool();
        $this->configureJwtService();

        // set phpseclib constants if applicable
        $this->setPhpsecConstants();
    }

    /**
     * Verifies an id token and returns the authenticated apiLoginTicket.
     * Throws an exception if the id token is not valid.
     * The audience parameter can be used to control which id tokens are
     * accepted.  By default, the id token must have been issued to this OAuth2 client.
     *
     * @param string $token The JSON Web Token to be verified.
     * @param string $audience [optional] The indended recipient of the token.
     * @param string $certsLocation [optional] The location (remote or local)
     *        from which to retrieve certificates, if not cached. This value
     *        should only be provided in limited circumstances in which you are
     *        sure of the behavior.
     * @return array|bool the token payload, if successful, or false if not.
     */
    public function verify($token, $audience = null, $certsLocation = null)
    {
        // Check signature against each available cert.
        // allow the loop to complete unless a known bad result is encountered.
        $certs = $this->getFederatedSignOnCerts($certsLocation);
        foreach ($certs as $cert) {
            $rsa = new RSA();
            $rsa->loadKey([
                'n' => new BigInteger($this->callJwtStatic('urlsafeB64Decode', [
                    $cert['n']
                ]), 256),
                'e' => new BigInteger($this->callJwtStatic('urlsafeB64Decode', [
                    $cert['e']
                ]), 256)
            ]);

            try {
                $pubkey = $rsa->getPublicKey();
                $payload = $this->callJwtStatic('decode', [
                    $token,
                    $pubkey,
                    ['RS256']
                ]);

                if (property_exists($payload, 'aud')) {
                    if ($audience && $payload->aud != $audience) {
                        return false;
                    }
                }

                // support HTTP and HTTPS issuers
                // @see https://developers.google.com/identity/sign-in/web/backend-auth
                $issuers = array(self::OAUTH2_ISSUER, self::OAUTH2_ISSUER_HTTPS);
                if (!isset($payload->iss) || !in_array($payload->iss, $issuers)) {
                    return false;
                }

                return (array) $payload;
            } catch (ExpiredException $e) {
                return false;
            } catch (SignatureInvalidException $e) {
                // continue
            } catch (\DomainException $e) {
                // continue
            }
        }

        return false;
    }

    /**
     * Revoke an OAuth2 access token or refresh token. This method will revoke the current access
     * token, if a token isn't provided.
     *
     * @param string|array $token The token (access token or a refresh token) that should be revoked.
     * @return boolean Returns True if the revocation was successful, otherwise False.
     */
    public function revoke($token)
    {
        if (is_array($token)) {
            if (isset($token['refresh_token'])) {
                $token = $token['refresh_token'];
            } else {
                $token = $token['access_token'];
            }
        }

        $body = Psr7\stream_for(http_build_query(['token' => $token]));
        $request = new Request('POST', self::OAUTH2_REVOKE_URI, [
            'Cache-Control' => 'no-store',
            'Content-Type'  => 'application/x-www-form-urlencoded',
        ], $body);

        $httpHandler = $this->httpHandler;

        $response = $httpHandler($request);

        return $response->getStatusCode() == 200;
    }

    /**
     * Gets federated sign-on certificates to use for verifying identity tokens.
     * Returns certs as array structure, where keys are key ids, and values
     * are PEM encoded certificates.
     *
     * @param string $location [optional] The location from which to retrieve
     *        certs.
     * @return array
     */
    private function getFederatedSignOnCerts($location = null)
    {
        $cacheItem = $this->cache->getItem('federated_signon_certs_v3');
        $certs = $cacheItem ? $cacheItem->get() : null;

        $gotNewCerts = false;
        if (!$certs) {
            $certs = $this->retrieveCertsFromLocation(
                $location ?: self::FEDERATED_SIGNON_CERT_URL
            );

            $gotNewCerts = true;
        }

        if (!isset($certs['keys'])) {
            throw new \InvalidArgumentException(
                'federated sign-on certs expects "keys" to be set'
            );
        }

        // Push cacheing off until after verifying certs are in a valid format.
        // Don't want to cache bad data.
        if ($gotNewCerts) {
            $cacheItem->expiresAt(new \DateTime('+1 hour'));
            $cacheItem->set($certs);
            $this->cache->save($cacheItem);
        }

        return $certs['keys'];
    }

    /**
     * Retrieve and cache a certificates file.
     *
     * @param $url string location
     * @throws \RuntimeException
     * @return array certificates
     */
    private function retrieveCertsFromLocation($url)
    {
        // If we're retrieving a local file, just grab it.
        if (strpos($url, 'http') !== 0) {
            if (!file_exists($url)) {
                throw new \InvalidArgumentException(sprintf(
                    'Failed to retrieve verification certificates from path: %s.',
                    $url
                ));
            }

            return json_decode(file_get_contents($url), true);
        }

        $httpHandler = $this->httpHandler;
        $response = $httpHandler(new Request('GET', $url));

        if ($response->getStatusCode() == 200) {
            return json_decode((string) $response->getBody(), true);
        }

        throw new \RuntimeException(sprintf(
            'Failed to retrieve verification certificates: "%s".',
            $response->getBody()->getContents()
        ), $response->getStatusCode());
    }

    /**
     * Set required defaults for JWT.
     */
    private function configureJwtService()
    {
        if (property_exists('Firebase\JWT\JWT', 'leeway') && JWT::$leeway < 1) {
            // Ensures JWT leeway is at least 1
            // @see https://github.com/google/google-api-php-client/issues/827
            JWT::$leeway = 1;
        }
    }

    /**
     * phpseclib calls "phpinfo" by default, which requires special
     * whitelisting in the AppEngine VM environment. This function
     * sets constants to bypass the need for phpseclib to check phpinfo
     *
     * @see phpseclib/Math/BigInteger
     * @see https://github.com/GoogleCloudPlatform/getting-started-php/issues/85
     * @codeCoverageIgnore
     */
    private function setPhpsecConstants()
    {
        if (filter_var(getenv('GAE_VM'), FILTER_VALIDATE_BOOLEAN)) {
            if (!defined('MATH_BIGINTEGER_OPENSSL_ENABLED')) {
                define('MATH_BIGINTEGER_OPENSSL_ENABLED', true);
            }
            if (!defined('CRYPT_RSA_MODE')) {
                define('CRYPT_RSA_MODE', RSA::MODE_OPENSSL);
            }
        }
    }

    /**
     * Provide a hook to mock calls to the JWT static methods.
     *
     * @param string $method
     * @param array $args
     * @return mixed
     */
    protected function callJwtStatic($method, array $args = [])
    {
        return call_user_func_array(['Firebase\JWT\JWT', $method], $args);
    }
}
