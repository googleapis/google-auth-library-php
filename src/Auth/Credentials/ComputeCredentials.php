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

use Google\Auth\Compute;
use Google\Auth\Jwt\ClientFactory;
use Google\Auth\SignBlob\ServiceAccountApiSignBlobTrait;
use Google\Auth\SignBlob\SignBlobInterface;
use Google\Http\ClientInterface as HttpClientInterface;
use Google\Jwt\ClientInterface as JwtClientInterface;
use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;

/**
 * ComputeCredentials supports authorization on Google Compute Engine.
 *
 * It can be used to authorize requests using the AuthTokenMiddleware, but will
 * only succeed if being run on GCE:
 *
 *   use Google\Auth\Credentials\ComputeCredentials;
 *   use Google\Auth\Http\CredentialsClient;
 *   use Psr\Http\Message\Request;
 *
 *   $gce = new ComputeCredentials();
 *   $http = new CredentialsClient($gce);
 *
 *   $url = 'https://www.googleapis.com/taskqueue/v1beta2/projects';
 *   $res = $http->send(new Request('GET', $url));
 */
class ComputeCredentials implements
    CredentialsInterface,
    SignBlobInterface
{
    use CredentialsTrait;
    use ServiceAccountApiSignBlobTrait;

    /**
     * The metadata path of the default token.
     */
    private const ACCESS_TOKEN_URI_PATH = '/computeMetadata/v1/instance/service-accounts/default/token';

    /**
     * The metadata path of the default id token.
     */
    private const ID_TOKEN_URI_PATH = '/computeMetadata/v1/instance/service-accounts/default/identity';

    /**
     * The metadata path of the client ID.
     */
    private const CLIENT_EMAIL_URI_PATH = '/computeMetadata/v1/instance/service-accounts/default/email';

    /**
     * The metadata path of the project ID.
     */
    private const PROJECT_ID_URI_PATH = '/computeMetadata/v1/project/project-id';

    /**
     * @var null|string
     */
    private $clientEmail;

    /**
     * @var null|string
     */
    private $projectId;

    /**
     * @var null|string
     */
    private $targetAudience;

    /**
     * @var null|array
     */
    private $scope;

    /**
     * @var null|string
     */
    private $quotaProject;

    /**
     * @var null|string
     */
    private $serviceAccountIdentity;

    /**
     * @var HttpClientInterface
     */
    private $httpClient;

    /**
     * @var string
     */
    private $tokenUri;

    /**
     * @var JwtClientInterface
     */
    private $jwtClient;

    /**
     * @param array                  $options
     * @param array|string           $options.scope                  the scope of the access request,
     *                                                               expressed either as an array or as a space-delimited string.
     * @param string                 $options.targetAudience         The audience for the ID token.
     * @param string                 $options.quotaProject           Specifies a project to bill for access
     *                                                               charges associated with the request.
     * @param string                 $options.serviceAccountIdentity [optional] Specify a service
     *                                                               account identity name to use instead of "default".
     * @param HttpClientInterface    $options.httpClient
     * @param JwtClientInterface     $options.jwtClient
     * @param CacheItemPoolInterface $options.cache
     * @param string                 $options.cachePrefix
     * @param int                    $options.cacheLifetime
     */
    public function __construct(array $options = [])
    {
        $options += [
            'httpClient' => null,
            'quotaProject' => null,
            'serviceAccountIdentity' => null,
            'scope' => null,
            'targetAudience' => null,
            'jwtClient' => null,
        ];

        if (isset($options['scope'], $options['targetAudience'])) {
            throw new InvalidArgumentException(
                'Scope and targetAudience cannot both be supplied'
            );
        }

        $this->setCacheFromOptions($options);
        $this->setHttpClientFromOptions($options);

        $this->jwtClient = $options['jwtClient'] ?: ClientFactory::build();
        $this->quotaProject = $options['quotaProject'];
        $this->serviceAccountIdentity = $options['serviceAccountIdentity'];
        $this->scope = is_string($options['scope'])
            ? explode(' ', $options['scope'])
            : $options['scope'];
        $this->targetAudience = $options['targetAudience'];
        $this->tokenUri = $this->getAuthTokenUriPath();
    }

    /**
     * Get the client name from GCE metadata.
     *
     * Subsequent calls will return a cached value.
     *
     * @return string
     */
    public function getClientEmail(): string
    {
        if ($this->clientEmail) {
            return $this->clientEmail;
        }

        return $this->clientEmail = Compute::getFromMetadata(
            self::getClientEmailUriPath($this->serviceAccountIdentity),
            $this->httpClient
        );
    }

    /**
     * Sign a string using the default service account private key.
     *
     * This implementation uses IAM's signBlob API.
     *
     * @see https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/signBlob SignBlob
     *
     * @param string $stringToSign the string to sign
     *
     * @return string
     */
    public function signBlob(string $stringToSign): string
    {
        $accessToken = $this->fetchAuthToken()['access_token'];

        return $this->signBlobWithServiceAccountApi(
            $this->getClientEmail(),
            $accessToken,
            $stringToSign,
            $this->httpClient
        );
    }

    /**
     * Fetch the default Project ID from compute engine.
     *
     * Returns null if called outside GCE.
     *
     * @return null|string
     */
    public function getProjectId(): ?string
    {
        if ($this->projectId) {
            return $this->projectId;
        }

        return $this->projectId = Compute::getFromMetadata(
            self::PROJECT_ID_URI_PATH,
            $this->httpClient
        );
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
     * Implements CredentialsInterface#fetchAuthToken.
     *
     * Fetches the auth tokens from the compute metadata host if it is available.
     * If $httpClient is not specified a the default HTTP Client is used.
     *
     * Access tokens have the following keys:
     *   - access_token (string)
     *   - expires_in   (int)
     *   - expires_at   (int)
     *   - token_type   (string)
     *
     * ID tokens have the following keys:
     *   - id_token   (string)
     *   - expires_at (int)
     *
     * @param ClientInterface $httpClient callback which delivers psr7 request
     *
     * @throws \Exception
     *
     * @return array a set of auth related metadata, based on the token type
     */
    private function fetchAuthTokenNoCache(): array
    {
        $response = Compute::getFromMetadata($this->tokenUri, $this->httpClient);

        if ($this->targetAudience) {
            $exp = $this->jwtClient->getExpirationWithoutVerification($response);

            return [
                'id_token' => $response,
                'expires_at' => $exp,
            ];
        }

        if (null === $json = json_decode($response, true)) {
            throw new \Exception('Invalid JSON response');
        }

        $json['expires_at'] = time() + $json['expires_in'];

        return $json;
    }

    private function getCacheKey(): string
    {
        return $this->tokenUri;
    }

    /**
     * The uri path for accessing the auth token.
     *
     * @return string
     */
    private function getAuthTokenUriPath(): string
    {
        if ($this->targetAudience) {
            $uriPath = self::ID_TOKEN_URI_PATH;
            $uriPath .= '?audience=' . $this->targetAudience;
        } else {
            $uriPath = self::ACCESS_TOKEN_URI_PATH;
            if ($this->scope) {
                $uriPath .= '?scopes=' . implode(',', $this->scope);
            }
        }

        if ($this->serviceAccountIdentity) {
            return str_replace(
                '/default/',
                '/' . $this->serviceAccountIdentity . '/',
                $uriPath
            );
        }

        return $uriPath;
    }

    /**
     * The full uri for accessing the default service account.
     *
     * @param string $serviceAccountIdentity Specify a service account identity
     *                                       name to use instead of "default"
     *
     * @return string
     */
    private static function getClientEmailUriPath(
        string $serviceAccountIdentity = null
    ): string {
        $uriPath = self::CLIENT_EMAIL_URI_PATH;

        if ($serviceAccountIdentity) {
            return str_replace(
                '/default/',
                '/' . $serviceAccountIdentity . '/',
                $uriPath
            );
        }

        return $uriPath;
    }
}
