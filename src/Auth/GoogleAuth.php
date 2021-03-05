<?php
/*
 * Copyright 2020 Google Inc.
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

declare(strict_types=1);

namespace Google\Auth;

use DomainException;
use Google\Auth\Credentials\ComputeCredentials;
use Google\Auth\Credentials\CredentialsInterface;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\UserRefreshCredentials;
use Google\Auth\Http\ClientFactory as HttpClientFactory;
use Google\Auth\Jwt\ClientFactory as JwtClientFactory;
use Google\Cache\MemoryCacheItemPool;
use Google\Http\ClientInterface as HttpClientInterface;
use Google\Jwt\ClientInterface as JwtClientInterface;
use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;
use Psr\Cache\CacheItemPoolInterface;
use RuntimeException;
use UnexpectedValueException;

/**
 * GoogleAuth obtains the default credentials for authorizing a request to a
 * Google service.
 *
 * Application Default Credentials are described here:
 * https://developers.google.com/accounts/docs/application-default-credentials
 *
 * This class implements the search for the application default credentials as
 * described in the link.
 *
 * This allows it to be used as follows (by default with GuzzleHttp\Client):
 *
 * ```
 * use Google\Auth\GoogleAuth;
 * use Google\Auth\Http\CredentialsClient;
 * use GuzzleHttp\Psr7\Request;
 *
 * $auth = new GoogleAuth();
 * $credentials = $auth->makeCredentials(
 *     'https://www.googleapis.com/auth/taskqueue' // task queue scope
 * );
 *
 * $client = new CredentialsClient($credentials);
 *
 * $baseUri = 'https://www.googleapis.com/taskqueue/v1beta2/projects/';
 * $request = new Request('GET', $baseUri . 'myproject/taskqueues/myqueue');
 * $response = $client->send($request);
 * ```
 */
class GoogleAuth
{
    const OIDC_CERT_URI = 'https://www.googleapis.com/oauth2/v3/certs';
    const OIDC_ISSUERS = ['https://accounts.google.com', 'http://accounts.google.com'];
    const IAP_JWK_URI = 'https://www.gstatic.com/iap/verify/public_key-jwk';
    const IAP_ISSUERS = ['https://cloud.google.com/iap'];

    private const ENV_VAR = 'GOOGLE_APPLICATION_CREDENTIALS';
    private const WELL_KNOWN_PATH = 'gcloud/application_default_credentials.json';
    private const NON_WINDOWS_WELL_KNOWN_PATH_BASE = '.config';

    private $cache;
    private $cacheLifetime;
    private $cachePrefix;
    private $httpClient;
    private $jwtClient;

    /**
     * Obtains an AuthTokenMiddleware which will fetch an access token to use in
     * the Authorization header. The middleware is configured with the default
     * FetchAuthTokenInterface implementation to use in this environment.
     *
     * If supplied, $scope is used to in creating the credentials instance if
     * this does not fallback to the Compute Engine defaults.
     *
     * @param array                  $options
     * @param HttpClientInterface    $options.httpClient    client which delivers psr7 request
     * @param JwtClientInterface     $options.jwtClient
     * @param CacheItemPoolInterface $options.cache         A cache implementation, may be
     *                                                      provided if you have one already available for use.
     * @param int                    $options.cacheLifetime
     * @param string                 $options.cachePrefix
     */
    public function __construct(array $options = [])
    {
        $options += [
            'cache' => null,
            'cacheLifetime' => 1500,
            'cachePrefix' => '',
            'httpClient' => null,
            'jwtClient' => null,
        ];
        $this->cache = $options['cache'] ?: new MemoryCacheItemPool();
        $this->cacheLifetime = $options['cacheLifetime'];
        $this->cachePrefix = $options['cachePrefix'];
        $this->httpClient = $options['httpClient'] ?: HttpClientFactory::build();
        $this->jwtClient = $options['jwtClient'] ?: JwtClientFactory::build();
    }

    /**
     * Obtains an AuthTokenMiddleware which will fetch an access token to use in
     * the Authorization header. The middleware is configured with the default
     * FetchAuthTokenInterface implementation to use in this environment.
     *
     * If supplied, $scope is used to in creating the credentials instance if
     * this does not fallback to the Compute Engine defaults.
     *
     * @param array        $options
     * @param array|string $opions.scope          the scope of the access request, expressed
     *                                            either as an Array or as a space-delimited String.
     * @param string       $opions.targetAudience The audience for the ID token.
     * @param string       $opions.audience
     * @param string       $opions.quotaProject   specifies a project to bill for access
     *                                            charges associated with the request.
     * @param string       $opions.subject
     * @param array|string $opions.defaultScope   The default scope to use if no
     *                                            user-defined scopes exist, expressed either as an Array or as
     *                                            a space-delimited string.
     *
     * @throws DomainException if no implementation can be obtained
     *
     * @return CredentialsInterface
     */
    public function makeCredentials(array $options = []): CredentialsInterface
    {
        $options += [
            'scope' => null,
            'targetAudience' => null,
            'audience' => null,
            'quotaProject' => null,
            'subject' => null,
            'credentialsFile' => null,
            'defaultScope' => null,
        ];

        if (is_null($options['credentialsFile'])) {
            $jsonKey = $this->fromEnv() ?: $this->fromWellKnownFile();
        } else {
            if (!file_exists($options['credentialsFile'])) {
                throw new InvalidArgumentException('Unable to read credentialsFile');
            }
            $jsonContents = file_get_contents($options['credentialsFile']);
            $jsonKey = json_decode($jsonContents, true);
        }

        $credentials = null;
        $anyScope = $options['scope'] ?: $options['defaultScope'];
        if (!is_null($jsonKey)) {
            if (!array_key_exists('type', $jsonKey)) {
                throw new \InvalidArgumentException(
                    'json key is missing the type field'
                );
            }

            // Set quota project on jsonKey if passed in
            if (isset($options['quotaProject'])) {
                $jsonKey['quota_project_id'] = $options['quotaProject'];
            }

            switch ($jsonKey['type']) {
                case 'service_account':
                    $credentials = new ServiceAccountCredentials($jsonKey, [
                        'scope' => $options['scope'],
                        'targetAudience' => $options['targetAudience'],
                        'httpClient' => $this->httpClient,
                        'subject' => $options['subject'],
                    ]);

                    break;

                case 'authorized_user':
                    if (isset($options['targetAudience'])) {
                        throw new InvalidArgumentException(
                            'ID tokens are not supported for end user credentials'
                        );
                    }
                    $credentials = new UserRefreshCredentials($jsonKey, [
                        'scope' => $anyScope,
                        'httpClient' => $this->httpClient,
                    ]);

                    break;

                default:
                    throw new \InvalidArgumentException(
                        'invalid value in the type field'
                    );
            }
        } elseif ($this->onCompute()) {
            $credentials = new ComputeCredentials([
                'scope' => $anyScope,
                'quotaProject' => $options['quotaProject'],
                'httpClient' => $this->httpClient,
                'targetAudience' => $options['targetAudience'],
            ]);
        }

        if (is_null($credentials)) {
            throw new DomainException(
                'Could not load the default credentials. Browse to '
                . 'https://developers.google.com/accounts/docs/application-default-credentials'
                . ' for more information'
            );
        }

        return $credentials;
    }

    /**
     * Determines if this a GCE instance, by accessing the expected metadata
     * host.
     *
     * @return bool
     */
    public function onCompute(array $options = []): bool
    {
        $cacheKey = 'google_auth_on_gce_cache';
        $cacheItem = $this->cache->getItem($this->cachePrefix . $cacheKey);

        if ($cacheItem->isHit()) {
            return $cacheItem->get();
        }

        $onCompute = Compute::onCompute($this->httpClient);
        $cacheItem->set($onCompute);
        $cacheItem->expiresAfter($this->cacheLifetime);
        $this->cache->save($cacheItem);

        return $onCompute;
    }

    /**
     * @param string $token                 the JSON Web Token to be verified
     * @param array  $options               [optional] Configuration options
     * @param string $options.audience      The indended recipient of the token.
     * @param string $options.cacheKey      cache key used for caching certs
     * @param string $options.certsLocation URI for JSON certificate array conforming to
     *                                      the JWK spec (see https://tools.ietf.org/html/rfc7517).
     * @param string $options.issuer        The intended issuer of the token.
     *
     * @return array the verified ID token payload
     */
    public function verify(string $token, array $options = []): array
    {
        $options += [
            'audience' => null,
            'certsLocation' => null,
            'cacheKey' => null,
            'issuer' => null,
        ];
        $location = $options['certsLocation'] ?: self::OIDC_CERT_URI;
        $cacheKey = $options['cacheKey'] ?:
            sprintf('google_auth_certs_cache|%s', sha1($location));

        $certs = $this->getCerts($location, $cacheKey);
        $alg = $this->determineAlg($certs);

        $keys = $this->jwtClient->parseKeySet($certs);
        $payload = $this->jwtClient->decode($token, $keys, [$alg]);

        $issuers = (array) $options['issuer'] ?:
            ['RS256' => self::OIDC_ISSUERS, 'ES256' => self::IAP_ISSUERS][$alg];

        if (empty($payload['iss']) || !in_array($payload['iss'], $issuers)) {
            throw new UnexpectedValueException('Issuer does not match');
        }

        $aud = $options['audience'] ?: null;
        if ($aud && isset($payload['aud']) && $payload['aud'] != $aud) {
            throw new UnexpectedValueException('Audience does not match');
        }

        return $payload;
    }

    /**
     * Gets federated sign-on certificates to use for verifying identity tokens.
     * Returns certs as array structure, where keys are key ids, and values
     * are PEM encoded certificates.
     *
     * @param string $location the location from which to retrieve certs
     * @param string $cacheKey the key under which to cache the retrieved certs
     *
     * @throws InvalidArgumentException if received certs are in an invalid format
     *
     * @return array
     */
    private function getCerts(string $location, string $cacheKey): array
    {
        $cacheItem = $this->cache->getItem($this->cachePrefix . $cacheKey);
        $certs = $cacheItem ? $cacheItem->get() : null;

        $gotNewCerts = false;
        if (!$certs) {
            $certs = $this->retrieveCertsFromLocation($location);

            $gotNewCerts = true;
        }

        if (!isset($certs['keys'])) {
            throw new InvalidArgumentException(
                'certs expects "keys" to be set'
            );
        }

        // Push caching off until after verifying certs are in a valid format.
        // Don't want to cache bad data.
        if ($gotNewCerts) {
            $cacheItem->expiresAfter($this->cacheLifetime);
            $cacheItem->set($certs);
            $this->cache->save($cacheItem);
        }

        return $certs;
    }

    /**
     * Identifies the expected algorithm to verify by looking at the "alg" key
     * of the provided certs.
     *
     * @param array $certs Certificate array according to the JWK spec (see
     *                     https://tools.ietf.org/html/rfc7517).
     *
     * @return string the expected algorithm, such as "ES256" or "RS256"
     */
    private function determineAlg(array $certs): string
    {
        $alg = null;
        foreach ($certs['keys'] as $cert) {
            if (empty($cert['alg'])) {
                throw new InvalidArgumentException(
                    'certs expects "alg" to be set'
                );
            }
            $alg = $alg ?: $cert['alg'];

            if ($alg != $cert['alg']) {
                throw new InvalidArgumentException(
                    'More than one alg detected in certs'
                );
            }
        }
        if (!in_array($alg, ['RS256', 'ES256'])) {
            throw new InvalidArgumentException(
                'unrecognized "alg" in certs, expected ES256 or RS256'
            );
        }

        return $alg;
    }

    /**
     * Retrieve and cache a certificates file.
     *
     * @param $url string location
     *
     * @throws InvalidArgumentException if certs could not be retrieved from a local file
     * @throws RuntimeException         if certs could not be retrieved from a remote location
     *
     * @return array certificates
     */
    private function retrieveCertsFromLocation(string $url): array
    {
        // If we're retrieving a local file, just grab it.
        if (0 !== strpos($url, 'http')) {
            if (!file_exists($url)) {
                throw new InvalidArgumentException(sprintf(
                    'Failed to retrieve verification certificates from path: %s.',
                    $url
                ));
            }

            return json_decode(file_get_contents($url), true);
        }

        $response = $this->httpClient->send(new Request('GET', $url));

        if (200 == $response->getStatusCode()) {
            return json_decode((string) $response->getBody(), true);
        }

        throw new RuntimeException(sprintf(
            'Failed to retrieve verification certificates: "%s".',
            $response->getBody()->getContents()
        ), $response->getStatusCode());
    }

    /**
     * Load a JSON key from the path specified in the environment.
     *
     * Load a JSON key from the path specified in the environment
     * variable GOOGLE_APPLICATION_CREDENTIALS. Return null if
     * GOOGLE_APPLICATION_CREDENTIALS is not specified.
     *
     * @return null|array
     */
    private function fromEnv(): ?array
    {
        $path = getenv(self::ENV_VAR);
        if (empty($path)) {
            return null;
        }
        if (!file_exists($path)) {
            $cause = 'file ' . $path . ' does not exist';

            throw new \DomainException(self::unableToReadEnv($cause));
        }
        $jsonKey = file_get_contents($path);

        return json_decode($jsonKey, true);
    }

    /**
     * Load a JSON key from a well known path.
     *
     * The well known path is OS dependent:
     *
     * * windows: %APPDATA%/gcloud/application_default_credentials.json
     * * others: $HOME/.config/gcloud/application_default_credentials.json
     *
     * If the file does not exist, this returns null.
     *
     * @return null|array
     */
    private function fromWellKnownFile(): ?array
    {
        $rootEnv = self::isOnWindows() ? 'APPDATA' : 'HOME';
        $path = [getenv($rootEnv)];
        if (!self::isOnWindows()) {
            $path[] = self::NON_WINDOWS_WELL_KNOWN_PATH_BASE;
        }
        $path[] = self::WELL_KNOWN_PATH;
        $path = implode(DIRECTORY_SEPARATOR, $path);
        if (!file_exists($path)) {
            return null;
        }
        $jsonKey = file_get_contents($path);

        return json_decode($jsonKey, true);
    }

    /**
     * @param string $cause
     *
     * @return string
     */
    private static function unableToReadEnv(string $cause): string
    {
        $msg = 'Unable to read the credential file specified by ';
        $msg .= ' GOOGLE_APPLICATION_CREDENTIALS: ';
        $msg .= $cause;

        return $msg;
    }

    /**
     * @return bool
     */
    private static function isOnWindows(): bool
    {
        return 'WIN' === strtoupper(substr(PHP_OS, 0, 3));
    }
}
