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

/**
 * Authenticates requests using Google's Service Account credentials via
 * JWT Access.
 *
 * This class allows authorizing requests for service accounts directly
 * from credentials from a json key file downloaded from the developer
 * console (via 'Generate new Json Key').  It is not part of any OAuth2
 * flow, rather it creates a JWT and sends that as a credential.
 */
class ServiceAccountJwtAccessCredentials implements
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
     */
    private $quotaProject;

    /**
     * Create a new ServiceAccountJwtAccessCredentials.
     *
     * @param array|string           $jsonKey               JSON credential file path or JSON credentials
     *                                                      as an associative array
     * @param array                  $options
     * @param string                 $options.audience
     * @param HttpClientInterface    $options.httpClient
     * @param CacheItemPoolInterface $options.cache
     * @param string                 $options.cachePrefix
     * @param int                    $options.cacheLifetime
     */
    public function __construct($jsonKey, array $options = [])
    {
        $options += [
            'audience' => null,
            'scope' => null,
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

        $this->setHttpClientFromOptions($options);
        $this->setCacheFromOptions($options);
        $this->throwExceptionForTargetAudience($options);

        $this->oauth2 = new OAuth2([
            'audience' => $options['audience'],
            'issuer' => $jsonKey['client_email'],
            'sub' => $jsonKey['client_email'],
            'signingAlgorithm' => 'RS256',
            'signingKey' => $jsonKey['private_key'],
            'scope' => $options['scope'],
            'httpClient' => $this->httpClient,
        ]);

        $this->projectId = isset($jsonKey['project_id'])
            ? $jsonKey['project_id']
            : null;
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
     * Get the quota project used for this API request.
     *
     * @return null|string
     */
    public function getQuotaProject(): ?string
    {
        return $this->quotaProject;
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
     * Returns metadata with the authorization token.
     *
     * @param string $authUri The optional uri being authorized
     *
     * @return array
     */
    public function getRequestMetadata(string $authUri = null): array
    {
        // no-op when audience is null if scope is also null
        if (empty($authUri) && empty($this->auth->getScope())) {
            return [];
        }

        $this->oauth2->setAudience($authUri);

        return $this->traitGetRequestMetadata($authUri);
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
     * Implements FetchAuthTokenInterface#fetchAuthToken. Returns an array
     * containing the following keys:
     *   - access_token (string)
     *   - expires_in (int)
     *
     * @return array A set of auth related metadata
     */
    private function fetchAuthTokenNoCache(): array
    {
        return [
            'access_token' => $this->oauth2->toJwt(),
            'expires_in' => $this->oauth2->getExpiry(),
        ];
    }

    /**
     * @return string
     */
    private function getCacheKey(): string
    {
        if ($cacheKey = $this->oauth2->getCacheKey()) {
            return $cacheKey;
        }

        throw new \LogicException('Unable to cache token without an audience');
    }
}
