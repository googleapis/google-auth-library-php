<?php
/*
 * Copyright 2020 Google LLC
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

namespace Google\Auth\Credentials;

use Google\Auth\OAuth2;
use Google\Auth\SignBlob\PrivateKeySignBlobTrait;
use Google\Auth\SignBlob\ServiceAccountApiSignBlobTrait;
use Google\Auth\SignBlob\SignBlobInterface;
use InvalidArgumentException;

/**
 * ServiceAccountCredentials supports authorization using a Google service
 * account.
 *
 * (cf https://developers.google.com/accounts/docs/OAuth2ServiceAccount)
 *
 * It's initialized using the json key file that's downloadable from developer
 * console, which should contain a private_key and client_email fields that it
 * uses.
 *
 * Use it with AuthTokenMiddleware to authorize http requests:
 *
 *   use Google\Auth\Credentials\ServiceAccountCredentials;
 *   use Google\Auth\Middleware\AuthTokenMiddleware;
 *   use GuzzleHttp\Client;
 *   use GuzzleHttp\HandlerStack;
 *
 *   $sa = new ServiceAccountCredentials(
 *       'https://www.googleapis.com/auth/taskqueue',
 *       '/path/to/your/json/key_file.json'
 *   );
 *   $middleware = new AuthTokenMiddleware($sa);
 *   $stack = HandlerStack::create();
 *   $stack->push($middleware);
 *
 *   $client = new Client([
 *       'handler' => $stack,
 *       'base_uri' => 'https://www.googleapis.com/taskqueue/v1beta2/projects/',
 *       'auth' => 'google_auth' // authorize all requests
 *   ]);
 *
 *   $res = $client->get('myproject/taskqueues/myqueue');
 */
class ServiceAccountCredentials implements
    CredentialsInterface,
    SignBlobInterface
{
    use CredentialsTrait {
        CredentialsTrait::getRequestMetadata as traitGetRequestMetadata;
    }
    use PrivateKeySignBlobTrait;
    use ServiceAccountApiSignBlobTrait;

    /**
     * The OAuth2 instance used to conduct authorization.
     *
     * @var OAuth2
     */
    private $oauth2;

    /**
     * The quota project associated with the JSON credentials.
     *
     * @var string
     */
    private $quotaProject;

    /**
     * @var null|string
     */
    private $projectId;

    /*
     * @var bool
     */
    private $useJwtAccessWithScope = false;

    /*
     * @var ServiceAccountJwtAccessCredentials|null
     */
    private $jwtAccessCredentials;

    /**
     * Create a new ServiceAccountCredentials.
     *
     * @param array|string           $jsonKey                JSON credential file path or JSON
     *                                                       credentials in associative array
     * @param array                  $options
     * @param array|string           $options.scope          the scope of the access request, expressed
     *                                                       as an array or as a space-delimited string
     * @param string                 $options.subject        an email address account to impersonate, in
     *                                                       situations when the service account has been delegated domain
     *                                                       wide access
     * @param string                 $options.targetAudience The audience for the ID token.
     * @param HttpClientInterface    $options.httpClient
     * @param CacheItemPoolInterface $options.cache
     * @param string                 $options.cachePrefix
     * @param int                    $options.cacheLifetime
     */
    public function __construct($jsonKey, array $options = [])
    {
        $options += [
            'scope' => null,
            'targetAudience' => null,
            'subject' => null,
        ];

        $jsonKey = $this->parseJsonKey($jsonKey);

        if (!array_key_exists('client_email', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the client_email field'
            );
        }
        if (!array_key_exists('private_key', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the private_key field'
            );
        }
        if ($options['scope'] && $options['targetAudience']) {
            throw new InvalidArgumentException(
                'Scope and targetAudience cannot both be supplied'
            );
        }
        $additionalClaims = [];
        if ($options['targetAudience']) {
            $additionalClaims = [
                'target_audience' => $options['targetAudience'],
            ];
        }
        $this->setHttpClientFromOptions($options);
        $this->setCacheFromOptions($options);

        $this->oauth2 = new OAuth2([
            'audience' => self::TOKEN_CREDENTIAL_URI,
            'tokenCredentialUri' => self::TOKEN_CREDENTIAL_URI,
            'signingAlgorithm' => 'RS256',
            'signingKey' => $jsonKey['private_key'],
            'issuer' => $jsonKey['client_email'],
            'scope' => $options['scope'],
            'sub' => $options['subject'],
            'additionalClaims' => $additionalClaims,
            'httpClient' => $this->httpClient,
        ]);

        $this->projectId = isset($jsonKey['project_id'])
            ? $jsonKey['project_id']
            : null;
    }

    /**
     * When called, the ServiceAccountCredentials will use an instance of
     * ServiceAccountJwtAccessCredentials to fetch (self-sign) an access token
     * even when only scopes are supplied. Otherwise,
     * ServiceAccountJwtAccessCredentials is only called when no scopes and an
     * authUrl (audience) is suppled.
     */
    public function useJwtAccessWithScope()
    {
        $this->useJwtAccessWithScope = true;
    }

    /**
     * @param callable $httpHandler
     *
     * @return array Auth related metadata, with the following keys:
     *     - access_token (string)
     *     - expires_in (int)
     *     - token_type (string)
     */
    private function fetchAuthTokenNoCache(): array
    {
        return $this->oauth2->fetchAuthToken();
    }

    /**
     * Get the project ID from the service account keyfile.
     *
     * Returns null if the project ID does not exist in the keyfile.
     *
     * @return null|string
     */
    public function getProjectId(): ?string
    {
        return $this->projectId;
    }

    /**
     * @param string $authUri The optional uri being authorized
     *
     * @return array metadata hashmap for request headers
     */
    public function getRequestMetadata(string $authUri = null): array
    {
        // scope exists. use oauth implementation
        if (!$this->useSelfSignedJwt()) {
            return $this->traitGetRequestMetadata();
        }

        // no scope found. create jwt with the auth uri
        $credJson = [
            'private_key' => $this->oauth2->getSigningKey(),
            'client_email' => $this->oauth2->getIssuer(),
        ];

        $options = [
            'httpClient' => $this->httpClient,
            'cache' => $this->cache,
            'cacheLifetime' => $this->cacheLifetime,
            'cachePrefix' => $this->cachePrefix,
        ];

        $jwtCreds = new ServiceAccountJwtAccessCredentials($credJson, $options);

        return $jwtCreds->getRequestMetadata($authUri);
    }

    private function createJwtAccessCredentials()
    {
        if (!$this->jwtAccessCredentials) {
            // Create credentials for self-signing a JWT (JwtAccess)
            $credJson = array(
                'private_key' => $this->auth->getSigningKey(),
                'client_email' => $this->auth->getIssuer(),
            );
            $this->jwtAccessCredentials = new ServiceAccountJwtAccessCredentials(
                $credJson,
                $this->auth->getScope()
            );
        }

        return $this->jwtAccessCredentials;
    }

    /**
     * Sign a string using the method which is best for a given credentials type.
     * If OpenSSL is not installed, uses the Service Account Credentials API.
     *
     * @param string $stringToSign the string to sign
     *
     * @return string The resulting signature. Value should be base64-encoded.
     */
    public function signBlob(string $stringToSign): string
    {
        try {
            return $this->signBlobWithPrivateKey(
                $stringToSign,
                $this->oauth2->getSigningKey()
            );
        } catch (\RuntimeException $e) {
        }

        $accessToken = $this->fetchAuthToken()['access_token'];

        return $this->signBlobWithServiceAccountApi(
            $this->httpClient,
            $this->getClientEmail(),
            $accessToken,
            $stringToSign
        );
    }

    /**
     * Get the client name from the keyfile.
     *
     * In this case, it returns the keyfile's client_email key.
     *
     * @return string
     */
    public function getClientEmail(): string
    {
        return $this->oauth2->getIssuer();
    }

    /**
     * Get the quota project used for this API request.
     *
     * @return null|string
     */
    public function getQuotaProject(): ?string
    {
        return $this->quotaProject;
    }

    /**
     * @return array Auth related metadata, with the following keys:
     *               - access_token (string)
     *               - expires_in (int)
     *               - token_type (string)
     */
    private function fetchAuthTokenNoCache(): array
    {
        return $this->oauth2->fetchAuthToken();
    }

    private function getCacheKey(): string
    {
        $key = $this->oauth2->getIssuer() . ':' . $this->oauth2->getCacheKey();
        if ($sub = $this->oauth2->getSub()) {
            $key .= ':' . $sub;
        }
        if ($claims = $this->oauth2->getAdditionalClaims()) {
            if (isset($claims['target_audience'])) {
                $key .= ':' . $claims['target_audience'];
            }
        }

        return $key;
    }

    private function useSelfSignedJwt()
    {
        // If claims are set, this call is for "id_tokens"
        if ($this->auth->getAdditionalClaims()) {
            return false;
        }

        // When true, ServiceAccountCredentials will always use JwtAccess for access tokens
        if ($this->useJwtAccessWithScope) {
            return true;
        }

        return is_null($this->auth->getScope());
    }
}
