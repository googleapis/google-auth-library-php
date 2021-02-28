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

use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Psr7\Query;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Google\Jwt\Client\FirebaseClient;
use Google\Auth\Http\ClientFactory as HttpClientFactory;
use Google\Auth\Jwt\ClientFactory as JwtClientFactory;
use Google\Http\ClientInterface as HttpClientInterface;
use Google\Jwt\ClientInterface as JwtClientInterface;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

/**
 * OAuth2 supports authentication by OAuth2 2-legged flows.
 *
 * It primary supports
 * - service account authorization
 * - authorization where a user already has an access token
 */
class OAuth2
{
    const JWT_URN = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    private const DEFAULT_EXPIRY_SECONDS = 3600; // 1 hour
    private const DEFAULT_SKEW_SECONDS = 60; // 1 minute

    /**
     * TODO: determine known methods from the keys of JWT::methods.
     */
    private static $knownSigningAlgorithms = [
        'HS256',
        'HS512',
        'HS384',
        'RS256',
    ];

    /**
     * The well known grant types.
     *
     * @var array
     */
    private static $knownGrantTypes = [
        'authorization_code',
        'refresh_token',
        'password',
        'client_credentials',
    ];

    /**
     * - authorizationUri
     *   The authorization server's HTTP endpoint capable of
     *   authenticating the end-user and obtaining authorization.
     *
     * @var UriInterface
     */
    private $authorizationUri;

    /**
     * - tokenCredentialUri
     *   The authorization server's HTTP endpoint capable of issuing
     *   tokens and refreshing expired tokens.
     *
     * @var UriInterface
     */
    private $tokenCredentialUri;

    /**
     * The redirection URI used in the initial request.
     *
     * @var string
     */
    private $redirectUri;

    /**
     * A unique identifier issued to the client to identify itself to the
     * authorization server.
     *
     * @var string
     */
    private $clientId;

    /**
     * A shared symmetric secret issued by the authorization server, which is
     * used to authenticate the client.
     *
     * @var string
     */
    private $clientSecret;

    /**
     * The resource owner's username.
     *
     * @var string
     */
    private $username;

    /**
     * The resource owner's password.
     *
     * @var string
     */
    private $password;

    /**
     * The scope of the access request, expressed either as an Array or as a
     * space-delimited string.
     *
     * @var array
     */
    private $scope;

    /**
     * An arbitrary string designed to allow the client to maintain state.
     *
     * @var string
     */
    private $state;

    /**
     * The authorization code issued to this client.
     *
     * Only used by the authorization code access grant type.
     *
     * @var string
     */
    private $code;

    /**
     * The issuer ID when using assertion profile.
     *
     * @var string
     */
    private $issuer;

    /**
     * The target audience for assertions.
     *
     * @var string
     */
    private $audience;

    /**
     * The target sub when issuing assertions.
     *
     * @var string
     */
    private $sub;

    /**
     * The number of seconds assertions are valid for.
     *
     * @var int
     */
    private $expiry;

    /**
     * The signing key when using assertion profile.
     *
     * @var string
     */
    private $signingKey;

    /**
     * The signing key id when using assertion profile. Param kid in jwt header.
     *
     * @var string
     */
    private $signingKeyId;

    /**
     * The signing algorithm when using an assertion profile.
     *
     * @var string
     */
    private $signingAlgorithm;

    /**
     * The refresh token associated with the access token to be refreshed.
     *
     * @var string
     */
    private $refreshToken;

    /**
     * The current access token.
     *
     * @var string
     */
    private $accessToken;

    /**
     * The current ID token.
     *
     * @var string
     */
    private $idToken;

    /**
     * The lifetime in seconds of the current access token.
     *
     * @var int
     */
    private $expiresIn;

    /**
     * The expiration time of the access token as a number of seconds since the
     * unix epoch.
     *
     * @var int
     */
    private $expiresAt;

    /**
     * The issue time of the access token as a number of seconds since the unix
     * epoch.
     *
     * @var int
     */
    private $issuedAt;

    /**
     * The current grant type.
     *
     * @var string
     */
    private $grantType;

    /**
     * When using an extension grant type, this is the set of parameters used by
     * that extension.
     */
    private $extensionParams;

    /**
     * When using the toJwt function, these claims will be added to the JWT
     * payload.
     */
    private $additionalClaims;

    /**
     * @var HttpClientInterface
     */
    private $httpClient;

    /**
     * @var JwtClientInterface
     */
    private $jwtClient;

    /**
     * Create a new OAuthCredentials.
     *
     * The configuration array accepts various options
     *
     * - authorizationUri
     *   The authorization server's HTTP endpoint capable of
     *   authenticating the end-user and obtaining authorization.
     *
     * - tokenCredentialUri
     *   The authorization server's HTTP endpoint capable of issuing
     *   tokens and refreshing expired tokens.
     *
     * - tokenRevokeUri
     *   The authorization server's HTTP endpoint capable of revoking access
     *   tokens.
     *
     * - clientId
     *   A unique identifier issued to the client to identify itself to the
     *   authorization server.
     *
     * - clientSecret
     *   A shared symmetric secret issued by the authorization server,
     *   which is used to authenticate the client.
     *
     * - scope
     *   The scope of the access request, expressed either as an Array
     *   or as a space-delimited String.
     *
     * - state
     *   An arbitrary string designed to allow the client to maintain state.
     *
     * - redirectUri
     *   The redirection URI used in the initial request.
     *
     * - username
     *   The resource owner's username.
     *
     * - password
     *   The resource owner's password.
     *
     * - issuer
     *   Issuer ID when using assertion profile
     *
     * - audience
     *   Target audience for assertions
     *
     * - expiry
     *   Number of seconds assertions are valid for
     *
     * - signingKey
     *   Signing key when using assertion profile
     *
     * - signingKeyId
     *   Signing key id when using assertion profile
     *
     * - extensionParams
     *   When using an extension grant type, this is the set of parameters used
     *   by that extension.
     *
     * @param array $config Configuration array
     */
    public function __construct(array $config = [])
    {
        $opts = array_merge([
            'credentialsFile' => null,
            'httpClient' => null,
            'jwtClient' => null,
            'expiry' => self::DEFAULT_EXPIRY_SECONDS,
            'extensionParams' => [],
            'authorizationUri' => null,
            'redirectUri' => null,
            'tokenCredentialUri' => null,
            'tokenRevokeUri' => null,
            'state' => null,
            'username' => null,
            'password' => null,
            'clientId' => null,
            'clientSecret' => null,
            'refreshToken' => null,
            'issuer' => null,
            'sub' => null,
            'audience' => null,
            'signingKey' => null,
            'signingKeyId' => null,
            'signingAlgorithm' => null,
            'scope' => null,
            'additionalClaims' => [],
        ], $config);

        if (isset($opts['credentialsFile'])) {
            if (!file_exists($opts['credentialsFile'])) {
                throw new InvalidArgumentException('Unable to read credentialsFile');
            }
            $creds = file_get_contents($opts['credentialsFile']);
            $jsonKey = json_decode($creds, true);
            if (!array_key_exists('type', $jsonKey)) {
                throw new \InvalidArgumentException('json key is missing the type field');
            }
            if (isset($jsonKey['client_id'])) {
                $opts['clientId'] = $jsonKey['client_id'];
            }
            if (isset($jsonKey['client_secret'])) {
                $opts['clientSecret'] = $jsonKey['client_secret'];
            }
            if (isset($jsonKey['refresh_token'])) {
                $opts['refreshToken'] = $jsonKey['refresh_token'];
            }
        }

        $this->httpClient = $opts['httpClient'] ?: HttpClientFactory::build();
        $this->jwtClient = $opts['jwtClient'] ?: JwtClientFactory::build();
        $this->setAuthorizationUri($opts['authorizationUri']);
        $this->setRedirectUri($opts['redirectUri']);
        $this->setTokenCredentialUri($opts['tokenCredentialUri']);
        $this->setTokenRevokeUri($opts['tokenRevokeUri']);
        $this->setState($opts['state']);
        $this->setUsername($opts['username']);
        $this->setPassword($opts['password']);
        $this->setClientId($opts['clientId']);
        $this->setClientSecret($opts['clientSecret']);
        $this->setRefreshToken($opts['refreshToken']);
        $this->setIssuer($opts['issuer']);
        $this->setSub($opts['sub']);
        $this->setExpiry($opts['expiry']);
        $this->setAudience($opts['audience']);
        $this->setSigningKey($opts['signingKey']);
        $this->setSigningKeyId($opts['signingKeyId']);
        $this->setSigningAlgorithm($opts['signingAlgorithm']);
        $this->setScope($opts['scope']);
        $this->setExtensionParams($opts['extensionParams']);
        $this->setAdditionalClaims($opts['additionalClaims']);
    }

    /**
     * Obtains the encoded jwt from the instance data.
     *
     * @param array $config array optional configuration parameters
     *
     * @return string
     */
    public function toJwt(array $config = [])
    {
        if (is_null($this->getSigningKey())) {
            throw new \DomainException('No signing key available');
        }
        if (is_null($this->getSigningAlgorithm())) {
            throw new \DomainException('No signing algorithm specified');
        }
        $now = time();

        $opts = array_merge([
            'skew' => self::DEFAULT_SKEW_SECONDS,
        ], $config);

        $assertion = [
            'iss' => $this->getIssuer(),
            'exp' => ($now + $this->getExpiry()),
            'iat' => ($now - $opts['skew']),
        ];
        foreach ($assertion as $k => $v) {
            if (is_null($v)) {
                throw new \DomainException($k . ' should not be null');
            }
        }
        if (!(is_null($this->getAudience()))) {
            $assertion['aud'] = $this->getAudience();
        }

        if (!(is_null($this->getScope()))) {
            $assertion['scope'] = $this->getScope();
        }

        if (empty($assertion['scope']) && empty($assertion['aud'])) {
            throw new \DomainException('one of scope or aud should not be null');
        }

        if (!(is_null($this->getSub()))) {
            $assertion['sub'] = $this->getSub();
        }
        $assertion += $this->getAdditionalClaims();

        return $this->jwtClient->encode(
            $assertion,
            $this->getSigningKey(),
            $this->getSigningAlgorithm(),
            $this->getSigningKeyId()
        );
    }

    /**
     * Fetches the auth tokens based on the current state.
     *
     * @return array the response
     */
    public function fetchAuthToken(): array
    {
        $response = $this->httpClient->send(
            $this->generateCredentialsRequest()
        );
        $credentials = $this->parseTokenResponse($response);
        $this->setAuthToken($credentials);

        return $credentials;
    }

    /**
     * Generates a request for token credentials.
     *
     * @return RequestInterface the authorization Url
     */
    public function generateCredentialsRequest(): RequestInterface
    {
        $uri = $this->getTokenCredentialUri();
        if (is_null($uri)) {
            throw new \DomainException('No token credential URI was set.');
        }

        $grantType = $this->getGrantType();
        $params = ['grant_type' => $grantType];

        switch ($grantType) {
            case 'authorization_code':
                $params['code'] = $this->getCode();
                $params['redirect_uri'] = $this->getRedirectUri();
                $this->addClientCredentials($params);

                break;

            case 'password':
                $params['username'] = $this->getUsername();
                $params['password'] = $this->getPassword();
                $this->addClientCredentials($params);

                break;

            case 'refresh_token':
                $params['refresh_token'] = $this->getRefreshToken();
                $this->addClientCredentials($params);

                break;

            case self::JWT_URN:
                $params['assertion'] = $this->toJwt();

                break;

            default:
                if (!is_null($this->getRedirectUri())) {
                    // Grant type was supposed to be 'authorization_code', as there
                    // is a redirect URI.
                    throw new \DomainException('Missing authorization code');
                }
                unset($params['grant_type']);
                if (!is_null($grantType)) {
                    $params['grant_type'] = $grantType;
                }
                $params = array_merge($params, $this->getExtensionParams());
        }

        $headers = [
            'Cache-Control' => 'no-store',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ];

        return new Request(
            'POST',
            $uri,
            $headers,
            Query::build($params)
        );
    }

    /**
     * Obtains a key that can used to cache the results of #fetchAuthToken.
     *
     * The key is derived from the scopes.
     *
     * @return string a key that may be used to cache the auth token
     */
    public function getCacheKey(): ?string
    {
        if (is_array($this->scope)) {
            return implode(':', $this->scope);
        }

        if ($this->audience) {
            return $this->audience;
        }

        // If scope has not set, return null to indicate no caching.
        return null;
    }

    /**
     * Sets properties of the OAuth2 token, usually after loading from cache.
     *
     * Example:
     * ```
     * $oauth->setAuthToken([
     *     'refresh_token' => 'n4E9O119d',
     *     'access_token' => 'FJQbwq9',
     *     'expires_in' => 3600
     * ]);
     * ```
     *
     * @param array $authToken
     *                         The configuration parameters related to the token.
     *
     *  - refresh_token
     *    The refresh token associated with the access token
     *    to be refreshed.
     *
     *  - access_token
     *    The current access token for this client.
     *
     *  - id_token
     *    The current ID token for this client.
     *
     *  - expires_in
     *    The time in seconds until access token expiration.
     *
     *  - expires_at
     *    The time as an integer number of seconds since the Epoch
     *
     *  - issued_at
     *    The timestamp that the token was issued at.
     */
    public function setAuthToken(array $authToken)
    {
        $opts = array_merge([
            'extensionParams' => [],
            'access_token' => null,
            'id_token' => null,
            'expires_in' => null,
            'expires_at' => null,
            'issued_at' => null,
        ], $authToken);

        $this->setExpiresAt($opts['expires_at']);
        $this->setExpiresIn($opts['expires_in']);

        // By default, the token is issued at `Time.now` when `expiresIn` is set,
        // but this can be used to supply a more precise time.
        if (!is_null($opts['issued_at'])) {
            $this->setIssuedAt($opts['issued_at']);
        }

        $this->setAccessToken($opts['access_token']);
        $this->setIdToken($opts['id_token']);

        // The refresh token should only be updated if a value is explicitly
        // passed in, as some access token responses do not include a refresh
        // token.
        if (array_key_exists('refresh_token', $opts)) {
            $this->setRefreshToken($opts['refresh_token']);
        }
    }

    /**
     * Revoke an OAuth2 access token or refresh token. This method will revoke the current access
     * token, if a token isn't provided.
     *
     * @param string $token the token (access token or a refresh token) that should be revoked
     *
     * @return bool returns True if the revocation was successful, otherwise False
     */
    public function revoke(string $token): bool
    {
        if (is_null($this->getTokenRevokeUri())) {
            throw new InvalidArgumentException(
                'requires an tokenRevokeUri to have been set'
            );
        }

        $body = Utils::streamFor(http_build_query(['token' => $token]));
        $request = new Request('POST', $this->tokenRevokeUri, [
            'Cache-Control' => 'no-store',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ], $body);

        $response = $this->httpClient->send($request);

        return 200 == $response->getStatusCode();
    }

    /**
     * Builds the authorization Uri that the user should be redirected to.
     *
     * @param array $config configuration options that customize the return url
     *
     * @throws InvalidArgumentException
     *
     * @return UriInterface the authorization Url
     */
    public function buildFullAuthorizationUri(array $config = [])
    {
        if (empty($this->getAuthorizationUri())) {
            throw new InvalidArgumentException(
                'requires an authorizationUri to have been set'
            );
        }

        $params = array_merge([
            'response_type' => 'code',
            'access_type' => 'offline',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'state' => $this->state,
            'scope' => $this->getScope(),
        ], $config);

        // Validate the auth_params
        if (is_null($params['client_id'])) {
            throw new InvalidArgumentException(
                'missing the required client identifier'
            );
        }
        if (is_null($params['redirect_uri'])) {
            throw new InvalidArgumentException('missing the required redirect URI');
        }
        if (!empty($params['prompt']) && !empty($params['approval_prompt'])) {
            throw new InvalidArgumentException(
                'prompt and approval_prompt are mutually exclusive'
            );
        }

        // Construct the uri object; return it if it is valid.
        $result = clone $this->authorizationUri;
        $existingParams = Query::parse($result->getQuery());

        $result = $result->withQuery(
            Query::build(array_merge($existingParams, $params))
        );

        if ('https' != $result->getScheme()) {
            throw new InvalidArgumentException(
                'Authorization endpoint must be protected by TLS'
            );
        }

        return $result;
    }

    /**
     * Gets the authorization server's HTTP endpoint capable of authenticating
     * the end-user and obtaining authorization.
     *
     * @return string
     */
    public function getAuthorizationUri(): ?string
    {
        return $this->authorizationUri
            ? (string) $this->authorizationUri
            : null;
    }

    /**
     * Sets the authorization server's HTTP endpoint capable of authenticating
     * the end-user and obtaining authorization.
     *
     * @param string $uri
     */
    public function setAuthorizationUri(?string $uri): void
    {
        $this->authorizationUri = $this->coerceUri($uri);
    }

    /**
     * Gets the authorization server's HTTP endpoint capable of issuing tokens
     * and refreshing expired tokens.
     *
     * @return string
     */
    public function getTokenCredentialUri(): ?string
    {
        return $this->tokenCredentialUri
            ? (string) $this->tokenCredentialUri
            : null;
    }

    /**
     * Sets the authorization server's HTTP endpoint capable of issuing tokens
     * and refreshing expired tokens.
     *
     * @param string $uri
     */
    public function setTokenCredentialUri(?string $uri): void
    {
        $this->tokenCredentialUri = $this->coerceUri($uri);
    }

    /**
     * Gets the authorization server's HTTP endpoint capable of revoking access
     * tokens.
     *
     * @return string
     */
    public function getTokenRevokeUri(): ?string
    {
        return $this->tokenRevokeUri ?
            (string) $this->tokenRevokeUri
            : null;
    }

    /**
     * Sets the authorization server's HTTP endpoint capable of revoking access
     * tokens.
     *
     * @param string $uri
     */
    public function setTokenRevokeUri(?string $uri): void
    {
        $this->tokenRevokeUri = $this->coerceUri($uri);
    }

    /**
     * Gets the redirection URI used in the initial request.
     *
     * @return string
     */
    public function getRedirectUri(): ?string
    {
        return $this->redirectUri
            ? (string) $this->redirectUri
            : null;
    }

    /**
     * Sets the redirection URI used in the initial request.
     *
     * @param string $uri
     */
    public function setRedirectUri(?string $uri): void
    {
        if (is_null($uri)) {
            $this->redirectUri = null;

            return;
        }
        // redirect URI must be absolute
        if (!$this->isAbsoluteUri($uri)) {
            // "postmessage" is a reserved URI string in Google-land
            // @see https://developers.google.com/identity/sign-in/web/server-side-flow
            if ('postmessage' !== (string) $uri) {
                throw new InvalidArgumentException(
                    'Redirect URI must be absolute'
                );
            }
        }
        $this->redirectUri = (string) $uri;
    }

    /**
     * Gets the scope of the access requests as a space-delimited String.
     *
     * @return string
     */
    public function getScope(): ?string
    {
        if (is_null($this->scope)) {
            return $this->scope;
        }

        return implode(' ', $this->scope);
    }

    /**
     * Sets the scope of the access request, expressed either as an Array or as
     * a space-delimited String.
     *
     * @param array|string $scope
     *
     * @throws InvalidArgumentException
     */
    public function setScope($scope): void
    {
        if (is_null($scope)) {
            $this->scope = null;
        } elseif (is_string($scope)) {
            $this->scope = explode(' ', $scope);
        } elseif (is_array($scope)) {
            foreach ($scope as $s) {
                $pos = strpos($s, ' ');
                if (false !== $pos) {
                    throw new InvalidArgumentException(
                        'array scope values should not contain spaces'
                    );
                }
            }
            $this->scope = $scope;
        } else {
            throw new InvalidArgumentException(
                'scopes should be a string or array of strings'
            );
        }
    }

    /**
     * Gets the current grant type.
     *
     * @return string
     */
    public function getGrantType(): ?string
    {
        if (!is_null($this->grantType)) {
            return $this->grantType;
        }

        // Returns the inferred grant type, based on the current object instance
        // state.
        if (!is_null($this->code)) {
            return 'authorization_code';
        }

        if (!is_null($this->refreshToken)) {
            return 'refresh_token';
        }

        if (!is_null($this->username) && !is_null($this->password)) {
            return 'password';
        }

        if (!is_null($this->issuer) && !is_null($this->signingKey)) {
            return self::JWT_URN;
        }

        return null;
    }

    /**
     * Sets the current grant type.
     *
     * @param $grantType
     *
     * @throws InvalidArgumentException
     */
    public function setGrantType($grantType): void
    {
        if (in_array($grantType, self::$knownGrantTypes)) {
            $this->grantType = $grantType;
        } else {
            // validate URI
            if (!$this->isAbsoluteUri($grantType)) {
                throw new InvalidArgumentException(
                    'invalid grant type'
                );
            }
            $this->grantType = (string) $grantType;
        }
    }

    /**
     * Gets an arbitrary string designed to allow the client to maintain state.
     *
     * @return string
     */
    public function getState(): ?string
    {
        return $this->state;
    }

    /**
     * Sets an arbitrary string designed to allow the client to maintain state.
     *
     * @param string $state
     */
    public function setState(?string $state): void
    {
        $this->state = $state;
    }

    /**
     * Gets the authorization code issued to this client.
     */
    public function getCode(): ?string
    {
        return $this->code;
    }

    /**
     * Sets the authorization code issued to this client.
     *
     * @param string $code
     */
    public function setCode(?string $code): void
    {
        $this->code = $code;
    }

    /**
     * Gets the resource owner's username.
     */
    public function getUsername(): ?string
    {
        return $this->username;
    }

    /**
     * Sets the resource owner's username.
     *
     * @param string $username
     */
    public function setUsername(?string $username): void
    {
        $this->username = $username;
    }

    /**
     * Gets the resource owner's password.
     */
    public function getPassword(): ?string
    {
        return $this->password;
    }

    /**
     * Sets the resource owner's password.
     *
     * @param $password
     */
    public function setPassword(?string $password): void
    {
        $this->password = $password;
    }

    /**
     * Sets a unique identifier issued to the client to identify itself to the
     * authorization server.
     */
    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    /**
     * Sets a unique identifier issued to the client to identify itself to the
     * authorization server.
     *
     * @param $clientId
     */
    public function setClientId(?string $clientId): void
    {
        $this->clientId = $clientId;
    }

    /**
     * Gets a shared symmetric secret issued by the authorization server, which
     * is used to authenticate the client.
     */
    public function getClientSecret(): ?string
    {
        return $this->clientSecret;
    }

    /**
     * Sets a shared symmetric secret issued by the authorization server, which
     * is used to authenticate the client.
     *
     * @param $clientSecret
     */
    public function setClientSecret(?string $clientSecret): void
    {
        $this->clientSecret = $clientSecret;
    }

    /**
     * Gets the Issuer ID when using assertion profile.
     */
    public function getIssuer(): ?string
    {
        return $this->issuer;
    }

    /**
     * Sets the Issuer ID when using assertion profile.
     *
     * @param string $issuer
     */
    public function setIssuer(?string $issuer): void
    {
        $this->issuer = $issuer;
    }

    /**
     * Gets the target sub when issuing assertions.
     */
    public function getSub(): ?string
    {
        return $this->sub;
    }

    /**
     * Sets the target sub when issuing assertions.
     *
     * @param string $sub
     */
    public function setSub(?string $sub): void
    {
        $this->sub = $sub;
    }

    /**
     * Gets the target audience when issuing assertions.
     */
    public function getAudience(): ?string
    {
        return $this->audience;
    }

    /**
     * Sets the target audience when issuing assertions.
     *
     * @param string $audience
     */
    public function setAudience(?string $audience): void
    {
        $this->audience = $audience;
    }

    /**
     * Gets the signing key when using an assertion profile.
     */
    public function getSigningKey(): ?string
    {
        return $this->signingKey;
    }

    /**
     * Sets the signing key when using an assertion profile.
     *
     * @param string $signingKey
     */
    public function setSigningKey(?string $signingKey): void
    {
        $this->signingKey = $signingKey;
    }

    /**
     * Gets the signing key id when using an assertion profile.
     *
     * @return string
     */
    public function getSigningKeyId(): ?string
    {
        return $this->signingKeyId;
    }

    /**
     * Sets the signing key id when using an assertion profile.
     *
     * @param string $signingKeyId
     */
    public function setSigningKeyId(?string $signingKeyId): void
    {
        $this->signingKeyId = $signingKeyId;
    }

    /**
     * Gets the signing algorithm when using an assertion profile.
     *
     * @return string
     */
    public function getSigningAlgorithm(): ?string
    {
        return $this->signingAlgorithm;
    }

    /**
     * Sets the signing algorithm when using an assertion profile.
     *
     * @param string $signingAlgorithm
     */
    public function setSigningAlgorithm(?string $signingAlgorithm): void
    {
        if (is_null($signingAlgorithm)) {
            $this->signingAlgorithm = null;
        } elseif (!in_array($signingAlgorithm, self::$knownSigningAlgorithms)) {
            throw new InvalidArgumentException('unknown signing algorithm');
        } else {
            $this->signingAlgorithm = $signingAlgorithm;
        }
    }

    /**
     * Gets the set of parameters used by extension when using an extension
     * grant type.
     */
    public function getExtensionParams(): array
    {
        return $this->extensionParams;
    }

    /**
     * Sets the set of parameters used by extension when using an extension
     * grant type.
     *
     * @param $extensionParams
     */
    public function setExtensionParams(array $extensionParams)
    {
        $this->extensionParams = $extensionParams;
    }

    /**
     * Gets the number of seconds assertions are valid for.
     */
    public function getExpiry(): ?int
    {
        return $this->expiry;
    }

    /**
     * Sets the number of seconds assertions are valid for.
     *
     * @param int $expiry
     */
    public function setExpiry(int $expiry): void
    {
        $this->expiry = $expiry;
    }

    /**
     * Gets the lifetime of the access token in seconds.
     */
    public function getExpiresIn(): ?int
    {
        return $this->expiresIn;
    }

    /**
     * Sets the lifetime of the access token in seconds.
     *
     * @param int $expiresIn
     */
    public function setExpiresIn(?int $expiresIn): void
    {
        if (is_null($expiresIn)) {
            $this->expiresIn = null;
            $this->issuedAt = null;
        } else {
            $this->issuedAt = time();
            $this->expiresIn = (int) $expiresIn;
        }
    }

    /**
     * Gets the time the current access token expires at.
     *
     * @return null|int
     */
    public function getExpiresAt(): ?int
    {
        if (!is_null($this->expiresAt)) {
            return $this->expiresAt;
        }

        if (!is_null($this->issuedAt) && !is_null($this->expiresIn)) {
            return $this->issuedAt + $this->expiresIn;
        }

        return null;
    }

    /**
     * Returns true if the acccess token has expired.
     *
     * @return bool
     */
    public function isExpired(): bool
    {
        $expiration = $this->getExpiresAt();
        $now = time();

        return is_null($expiration) || $now >= $expiration;
    }

    /**
     * Sets the time the current access token expires at.
     *
     * @param int $expiresAt
     */
    public function setExpiresAt(?int $expiresAt): void
    {
        $this->expiresAt = $expiresAt;
    }

    /**
     * Gets the time the current access token was issued at.
     *
     * @return null|int
     */
    public function getIssuedAt(): ?int
    {
        return $this->issuedAt;
    }

    /**
     * Sets the time the current access token was issued at.
     *
     * @param int $issuedAt
     */
    public function setIssuedAt(int $issuedAt): void
    {
        $this->issuedAt = $issuedAt;
    }

    /**
     * Gets the current access token.
     *
     * @return null|string
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }

    /**
     * Sets the current access token.
     *
     * @param null|string $accessToken
     */
    public function setAccessToken(string $accessToken = null): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Gets the current ID token.
     *
     * @return null|string
     */
    public function getIdToken(): ?string
    {
        return $this->idToken;
    }

    /**
     * Sets the current ID token.
     *
     * @param null|string $idToken
     */
    public function setIdToken(string $idToken = null): void
    {
        $this->idToken = $idToken;
    }

    /**
     * Gets the refresh token associated with the current access token.
     *
     * @return null|string
     */
    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    /**
     * Sets the refresh token associated with the current access token.
     *
     * @param null|string $refreshToken
     */
    public function setRefreshToken(?string $refreshToken): void
    {
        $this->refreshToken = $refreshToken;
    }

    /**
     * Gets the additional claims to be included in the JWT token.
     *
     * @return array
     */
    public function getAdditionalClaims(): array
    {
        return $this->additionalClaims;
    }

    /**
     * Sets additional claims to be included in the JWT token.
     *
     * @param array $additionalClaims
     */
    public function setAdditionalClaims(array $additionalClaims): void
    {
        $this->additionalClaims = $additionalClaims;
    }

    /**
     * Parses the fetched tokens.
     *
     * @param ResponseInterface $resp the response
     *
     * @throws \Exception
     *
     * @return array the tokens parsed from the response body
     */
    private function parseTokenResponse(ResponseInterface $resp): array
    {
        $body = (string) $resp->getBody();
        if ($resp->hasHeader('Content-Type')
            && 'application/x-www-form-urlencoded' == $resp->getHeaderLine('Content-Type')
        ) {
            $res = [];
            parse_str($body, $res);

            return $res;
        }

        // Assume it's JSON; if it's not throw an exception
        if (null === $res = json_decode($body, true)) {
            throw new \Exception('Invalid JSON response');
        }

        return $res;
    }

    /**
     * @param string $uri
     *
     * @return null|UriInterface
     */
    private function coerceUri(?string $uri): ?UriInterface
    {
        if (is_null($uri)) {
            return null;
        }

        return Utils::uriFor($uri);
    }

    /**
     * Determines if the URI is absolute based on its scheme and host or path
     * (RFC 3986).
     *
     * @param string $uri
     *
     * @return bool
     */
    private function isAbsoluteUri(string $uri): bool
    {
        $uri = $this->coerceUri($uri);

        return $uri->getScheme() && ($uri->getHost() || $uri->getPath());
    }

    /**
     * @param array $params
     */
    private function addClientCredentials(array &$params): void
    {
        $clientId = $this->getClientId();
        $clientSecret = $this->getClientSecret();

        if ($clientId && $clientSecret) {
            $params['client_id'] = $clientId;
            $params['client_secret'] = $clientSecret;
        }
    }
}
