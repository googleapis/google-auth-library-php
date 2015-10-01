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

namespace Google\Auth;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Collection;
use GuzzleHttp\Query;
use GuzzleHttp\Message\ResponseInterface;
use GuzzleHttp\Url;
use JWT;

/**
 * OAuth2 supports authentication by OAuth2 2-legged flows.
 *
 * It primary supports
 * - service account authorization
 * - authorization where a user already has an access token
 */
class OAuth2 implements FetchAuthTokenInterface
{

  const DEFAULT_EXPIRY_MINUTES = 60;
  const DEFAULT_SKEW = 60;
  const JWT_URN = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

  /**
   * TODO: determine known methods from the keys of JWT::methods
   */
  public static $knownSigningAlgorithms = array('HS256', 'HS512', 'HS384',
                                                'RS256');

  /**
   * The well known grant types.
   */
  public static $knownGrantTypes = array('authorization_code',
                                         'refresh_token',
                                         'password',
                                         'client_credentials');

  /**
   * - authorizationUri
   *   The authorization server's HTTP endpoint capable of
   *   authenticating the end-user and obtaining authorization.
   */
  private $authorizationUri;

  /**
   * - tokenCredentialUri
   *   The authorization server's HTTP endpoint capable of issuing
   *   tokens and refreshing expired tokens.
   */
  private $tokenCredentialUri;

  /**
   * The redirection URI used in the initial request.
   */
  private $redirectUri;

  /**
   * A unique identifier issued to the client to identify itself to the
   * authorization server.
   */
  private $clientId;

  /**
   * A shared symmetric secret issued by the authorization server, which is
   * used to authenticate the client.
   */
  private $clientSecret;

  /**
   * The resource owner's username.
   */
  private $username;

  /**
   * The resource owner's password.
   */
  private $password;

  /**
   * The scope of the access request, expressed either as an Array or as a
   * space-delimited string.
   */
  private $scope;

  /**
   * An arbitrary string designed to allow the client to maintain state.
   */
  private $state;

  /**
   * The authorization code issued to this client.
   *
   * Only used by the authorization code access grant type.
   */
  private $code;

  /**
   * The issuer ID when using assertion profile.
   */
  private $issuer;

  /**
   * The target audience for assertions.
   */
  private $audience;

  /**
   * The target user for assertions.
   */
  private $principal;

  /**
   * The target sub when issuing assertions.
   */
  private $sub;

  /**
   * The number of seconds assertions are valid for.
   */
  private $expiry;

  /**
   * The signing key when using assertion profile.
   */
  private $signingKey;

  /**
   * The signing algorithm when using an assertion profile.
   */
  private $signingAlgorithm;

  /**
   * The refresh token associated with the access token to be refreshed.
   */
  private $refreshToken;

  /**
   * The current access token.
   */
  private $accessToken;

  /**
   * The current ID token.
   */
  private $idToken;

  /**
   * The lifetime in seconds of the current access token.
   */
  private $expiresIn;

  /**
   * The expiration time of the access token as a number of seconds since the
   * unix epoch.
   */
  private $expiresAt;

  /**
   * The issue time of the access token as a number of seconds since the unix
   * epoch.
   */
  private $issuedAt;

  /**
   * The current grant type.
   */
  private $grantType;

  /**
   * When using an extension grant type, this is the set of parameters used by
   * that extension.
   */
  private $extensionParams;

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
   * - code
   *   The authorization code received from the authorization server.
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
   * - principal
   *   Target user for assertions
   *
   * - expiry
   *   Number of seconds assertions are valid for
   *
   * - signingKey
   *   Signing key when using assertion profile
   *
   * - refreshToken
   *   The refresh token associated with the access token
   *   to be refreshed.
   *
   * - accessToken
   *   The current access token for this client.
   *
   * - idToken
   *   The current ID token for this client.
   *
   * - extensionParams
   *   When using an extension grant type, this is the set of parameters used
   *   by that extension.
   *
   * @param array $config Configuration array
   */
  public function __construct(array $config)
  {
    $opts = Collection::fromConfig($config, [
        'expiry' => self::DEFAULT_EXPIRY_MINUTES,
        'extensionParams' => []
    ], []);
    $this->setAuthorizationUri($opts->get('authorizationUri'));
    $this->setRedirectUri($opts->get('redirectUri'));
    $this->setTokenCredentialUri($opts->get('tokenCredentialUri'));
    $this->setState($opts->get('state'));
    $this->setUsername($opts->get('username'));
    $this->setPassword($opts->get('password'));
    $this->setClientId($opts->get('clientId'));
    $this->setClientSecret($opts->get('clientSecret'));
    $this->setIssuer($opts->get('issuer'));
    $this->setPrincipal($opts->get('principal'));
    $this->setSub($opts->get('sub'));
    $this->setExpiry($opts->get('expiry'));
    $this->setAudience($opts->get('audience'));
    $this->setSigningKey($opts->get('signingKey'));
    $this->setSigningAlgorithm($opts->get('signingAlgorithm'));
    $this->setScope($opts->get('scope'));
    $this->setExtensionParams($opts->get('extensionParams'));
    $this->updateToken($config);
  }

 /**
  * Verifies the idToken if present.
  *
  * - if none is present, return null
  * - if present, but invalid, raises DomainException.
  * - otherwise returns the payload in the idtoken as a PHP object.
  *
  * if $publicKey is null, the key is decoded without being verified.
  *
  * @param $publicKey the publicKey to use to authenticate the token
  * @param Array $allowed_algs List of supported verification algorithms
  */
  public function verifyIdToken($publicKey = null, $allowed_algs = array())
  {
    $idToken = $this->getIdToken();
    if (is_null($idToken)) {
      return null;
    }

    $resp = JWT::decode($idToken, $publicKey, $allowed_algs);
    if (!property_exists($resp, 'aud')) {
      throw new \DomainException('No audience found the id token');
    }
    if ($resp->aud != $this->getAudience()) {
      throw new \DomainException('Wrong audience present in the id token');
    }
    return $resp;
  }

 /**
  * Obtains the encoded jwt from the instance data.
  *
  * @param $config array optional configuration parameters
  */
  public function toJwt(array $config = null)
  {
    if (is_null($this->getSigningKey())) {
      throw new \DomainException('No signing key available');
    }
    if (is_null($this->getSigningAlgorithm())) {
      throw new \DomainException('No signing algorithm specified');
    }
    $now = time();
    if (is_null($config)) {
      $config = [];
    }
    $opts = Collection::fromConfig($config, [
        'skew' => self::DEFAULT_SKEW,
    ], []);
    $assertion = [
        'iss' => $this->getIssuer(),
        'aud' => $this->getAudience(),
        'exp' => ($now + $this->getExpiry()),
        'iat' => ($now - $opts->get('skew'))
    ];
    foreach ($assertion as $k => $v) {
      if (is_null($v)) {
        throw new \DomainException($k . ' should not be null');
      }
    }
    if (!(is_null($this->getScope()))) {
      $assertion['scope'] = $this->getScope();
    }
    if (!(is_null($this->getPrincipal()))) {
      $assertion['prn'] = $this->getPrincipal();
    }
    if (!(is_null($this->getSub()))) {
      $assertion['sub'] = $this->getSub();
    }
    return JWT::encode($assertion, $this->getSigningKey(),
                       $this->getSigningAlgorithm());
  }

 /**
  * Generates a request for token credentials.
  *
  * @param $client GuzzleHttp\ClientInterface the optional client.
  * @return GuzzleHttp\RequestInterface the authorization Url.
  */
  public function generateCredentialsRequest(ClientInterface $client = null)
  {
    $uri = $this->getTokenCredentialUri();
    if (is_null($uri)) {
      throw new \DomainException('No token credential URI was set.');
    }
    if (is_null($client)) {
      $client = new Client();
    }
    $grantType = $this->getGrantType();
    $params = array('grant_type' => $grantType);
    switch($grantType) {
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
          # Grant type was supposed to be 'authorization_code', as there
          # is a redirect URI.
          throw new \DomainException('Missing authorization code');
        }
        unset($params['grant_type']);
        if (!is_null($grantType)) {
          $params['grant_type'] = strval($grantType);
        }
        $params = array_merge($params, $this->getExtensionParams());
    }
    $request = $client->createRequest('POST', $uri);
    $request->addHeader('Cache-Control', 'no-store');
    $request->addHeader('Content-Type', 'application/x-www-form-urlencoded');
    $request->getBody()->replaceFields($params);
    return $request;
  }

 /**
  * Fetchs the auth tokens based on the current state.
  *
  * @param $client GuzzleHttp\ClientInterface the optional client.
  * @return array the response
  */
  public function fetchAuthToken(ClientInterface $client = null)
  {
    if (is_null($client)) {
      $client = new Client();
    }
    $resp = $client->send($this->generateCredentialsRequest($client));
    $creds = $this->parseTokenResponse($resp);
    $this->updateToken($creds);
    return $creds;
  }

 /**
  * Obtains a key that can used to cache the results of #fetchAuthToken.
  *
  * The key is derived from the scopes.
  *
  * @return string a key that may be used to cache the auth token.
  */
  public function getCacheKey() {
    if (is_string($this->scope)) {
      return $this->scope;
    } else if (is_array($this->scope)) {
      return implode(":", $this->scope);
    }

    // If scope has not set, return null to indicate no caching.
    return null;
  }

 /**
  * Parses the fetched tokens.
  *
  * @param $resp GuzzleHttp\Message\ReponseInterface the response.
  * @return array the tokens parsed from the response body.
  */
  public function parseTokenResponse(ResponseInterface $resp)
  {
    $body = $resp->getBody()->getContents();
    if ($resp->hasHeader('Content-Type') &&
        $resp->getHeader('Content-Type') == 'application/x-www-form-urlencoded') {
      $res = array();
      parse_str($body, $res);
      return $res;
    } else {
      // Assume it's JSON; if it's not there needs to be an exception, so
      // we use the json decode exception instead of adding a new one.
      return $resp->json();
    }
  }

 /**
  * Updates an OAuth 2.0 client.
  *
  * @example
  *   client.updateToken([
  *     'refresh_token' => 'n4E9O119d',
  *     'access_token' => 'FJQbwq9',
  *     'expires_in' => 3600
  *   ])
  *
  * @param array options
  *  The configuration parameters related to the token.
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
  public function updateToken(array $config)
  {
    $opts = Collection::fromConfig($config, [
        'extensionParams' => []
    ], []);
    $this->setExpiresAt($opts->get('expires'));
    $this->setExpiresAt($opts->get('expires_at'));
    $this->setExpiresIn($opts->get('expires_in'));
    // By default, the token is issued at `Time.now` when `expiresIn` is set,
    // but this can be used to supply a more precise time.
    $this->setIssuedAt($opts->get('issued_at'));

    $this->setAccessToken($opts->get('access_token'));
    $this->setIdToken($opts->get('id_token'));
    $this->setRefreshToken($opts->get('refresh_token'));
  }

  /**
   * Builds the authorization Uri that the user should be redirected to.
   *
   * @param $config configuration options that customize the return url
   * @return GuzzleHttp::Url the authorization Url.
   */
  public function buildFullAuthorizationUri(array $config = null)
  {
    if (is_null($this->getAuthorizationUri())) {
      throw new \InvalidArgumentException(
          'requires an authorizationUri to have been set');
    }
    $defaults = [
        'response_type' => 'code',
        'access_type' => 'offline',
        'client_id' => $this->clientId,
        'redirect_uri' => $this->redirectUri,
        'state' => $this->state,
        'scope' => $this->getScope()
    ];
    $params = new Collection($defaults);
    if (!is_null($config)) {
      $params = Collection::fromConfig($config, $defaults, []);
    }

    // Validate the auth_params
    if (is_null($params->get('client_id'))) {
      throw new \InvalidArgumentException(
          'missing the required client identifier');
    }
    if (is_null($params->get('redirect_uri'))) {
      throw new \InvalidArgumentException('missing the required redirect URI');
    }
    if ($params->hasKey('prompt') && $params->hasKey('approval_prompt')) {
      throw new \InvalidArgumentException(
          'prompt and approval_prompt are mutually exclusive');
    }

    // Construct the uri object; return it if it is valid.
    $result = clone $this->authorizationUri;
    if (is_string($result)) {
      $result = Url::fromString($this->getAuthorizationUri());
    }
    $result->getQuery()->merge($params);
    if ($result->getScheme() != 'https') {
      throw new \InvalidArgumentException(
          'Authorization endpoint must be protected by TLS');
    }
    return $result;
  }

  /**
   * Sets the authorization server's HTTP endpoint capable of authenticating
   * the end-user and obtaining authorization.
   */
  public function setAuthorizationUri($uri)
  {
    $this->authorizationUri = $this->coerceUri($uri);
  }

  /**
   * Gets the authorization server's HTTP endpoint capable of authenticating
   * the end-user and obtaining authorization.
   */
  public function getAuthorizationUri()
  {
    return $this->authorizationUri;
  }

  /**
   * Gets the authorization server's HTTP endpoint capable of issuing tokens
   * and refreshing expired tokens.
   */
  public function getTokenCredentialUri()
  {
    return $this->tokenCredentialUri;
  }

  /**
   * Sets the authorization server's HTTP endpoint capable of issuing tokens
   * and refreshing expired tokens.
   */
  public function setTokenCredentialUri($uri)
  {
    $this->tokenCredentialUri = $this->coerceUri($uri);
  }

  /**
   * Gets the redirection URI used in the initial request.
   */
  public function getRedirectUri()
  {
    return $this->redirectUri;
  }

  /**
   * Sets the redirection URI used in the initial request.
   */
  public function setRedirectUri($uri)
  {
    if (is_null($uri)) {
      $this->redirectUri = null;
      return;
    }
    $u = $this->coerceUri($uri);
    if (!$this->isAbsoluteUri($u)) {
      throw new \InvalidArgumentException(
          'Redirect URI must be absolute');
    }
    $this->redirectUri = $u;
  }

  /**
   * Gets the scope of the access requests as a space-delimited String.
   */
  public function getScope()
  {
    if (is_null($this->scope)) {
      return $this->scope;
    }
    return implode(' ', $this->scope);
  }

  /**
   * Sets the scope of the access request, expressed either as an Array or as
   * a space-delimited String.
   */
  public function setScope($scope)
  {
    if (is_null($scope)) {
      $this->scope = null;
    } else if (is_string($scope)) {
      $this->scope = explode(' ', $scope);
    } else if (is_array($scope)) {
      foreach ($scope as $s) {
        $pos = strpos($s, ' ');
        if ($pos !== false) {
          throw new \InvalidArgumentException(
              'array scope values should not contain spaces');
        }
      }
      $this->scope = $scope;
    } else {
      throw new \InvalidArgumentException(
          'scopes should be a string or array of strings');
    }
  }

  /**
   * Gets the current grant type.
   */
  public function getGrantType()
  {
    if (!is_null($this->grantType)) {
      return $this->grantType;
    }

    // Returns the inferred grant type, based on the current object instance
    // state.
    if (!is_null($this->code) && !is_null($this->redirectUri)) {
      return 'authorization_code';
    } else if (!is_null($this->refreshToken)) {
      return 'refresh_token';
    } else if (!is_null($this->username) && !is_null($this->password)) {
      return 'password';
    } else if (!is_null($this->issuer) && !is_null($this->signingKey)) {
      return self::JWT_URN;
    } else {
      return null;
    }
  }

  /**
   * Sets the current grant type.
   */
  public function setGrantType($gt)
  {
    if (in_array($gt, self::$knownGrantTypes)) {
      $this->grantType = $gt;
    } else {
      $this->grantType = Url::fromString($gt);
    }
  }

  /**
   * Gets an arbitrary string designed to allow the client to maintain state.
   */
  public function getState()
  {
    return $this->state;
  }

  /**
   * Sets an arbitrary string designed to allow the client to maintain state.
   */
  public function setState($state)
  {
    $this->state = $state;
  }

  /**
   * Gets the authorization code issued to this client.
   */
  public function getCode()
  {
    return $this->code;
  }

  /**
   * Sets the authorization code issued to this client.
   */
  public function setCode($code)
  {
    $this->code = $code;
  }

  /**
   * Gets the resource owner's username.
   */
  public function getUsername()
  {
    return $this->username;
  }

  /**
   * Sets the resource owner's username.
   */
  public function setUsername($username)
  {
    $this->username = $username;
  }

  /**
   * Gets the resource owner's password.
   */
  public function getPassword()
  {
    return $this->password;
  }

  /**
   * Sets the resource owner's password.
   */
  public function setPassword($password)
  {
    $this->password = $password;
  }

  /**
   * Sets a unique identifier issued to the client to identify itself to the
   * authorization server.
   */
  public function getClientId()
  {
    return $this->clientId;
  }

  /**
   * Sets a unique identifier issued to the client to identify itself to the
   * authorization server.
   */
  public function setClientId($clientId)
  {
    $this->clientId = $clientId;
  }

  /**
   * Gets a shared symmetric secret issued by the authorization server, which
   * is used to authenticate the client.
   */
  public function getClientSecret()
  {
    return $this->clientSecret;
  }

  /**
   * Sets a shared symmetric secret issued by the authorization server, which
   * is used to authenticate the client.
   */
  public function setClientSecret($clientSecret)
  {
    $this->clientSecret = $clientSecret;
  }

  /**
   * Gets the Issuer ID when using assertion profile.
   */
  public function getIssuer()
  {
    return $this->issuer;
  }

  /**
   * Sets the Issuer ID when using assertion profile.
   */
  public function setIssuer($issuer)
  {
    $this->issuer = $issuer;
  }

  /**
   * Gets the target user for the assertions.
   */
  public function getPrincipal()
  {
    return $this->principal;
  }

  /**
   * Sets the target user for the assertions.
   */
  public function setPrincipal($p)
  {
    $this->principal = $p;
  }

  /**
   * Gets the target sub when issuing assertions.
   */
  public function getSub()
  {
    return $this->sub;
  }

  /**
   * Sets the target sub when issuing assertions.
   */
  public function setSub($sub)
  {
    $this->sub = $sub;
  }

  /**
   * Gets the target audience when issuing assertions.
   */
  public function getAudience()
  {
    return $this->audience;
  }

  /**
   * Sets the target audience when issuing assertions.
   */
  public function setAudience($audience)
  {
    $this->audience = $audience;
  }

  /**
   * Gets the signing key when using an assertion profile.
   */
  public function getSigningKey()
  {
    return $this->signingKey;
  }

  /**
   * Sets the signing key when using an assertion profile.
   */
  public function setSigningKey($signingKey)
  {
    $this->signingKey = $signingKey;
  }

  /**
   * Gets the signing algorithm when using an assertion profile.
   */
  public function getSigningAlgorithm()
  {
    return $this->signingAlgorithm;
  }

  /**
   * Sets the signing algorithm when using an assertion profile.
   */
  public function setSigningAlgorithm($sa)
  {
    if (is_null($sa)) {
      $this->signingAlgorithm = null;
    } else if (!in_array($sa, self::$knownSigningAlgorithms)) {
      throw new \InvalidArgumentException('unknown signing algorithm');
    } else {
      $this->signingAlgorithm = $sa;
    }
  }

  /**
   * Gets the set of parameters used by extension when using an extension
   * grant type.
   */
  public function getExtensionParams()
  {
    return $this->extensionParams;
  }

  /**
   * Sets the set of parameters used by extension when using an extension
   * grant type.
   */
  public function setExtensionParams($extensionParams)
  {
    $this->extensionParams = $extensionParams;
  }

  /**
   * Gets the number of seconds assertions are valid for.
   */
  public function getExpiry()
  {
    return $this->expiry;
  }

  /**
   * Sets the number of seconds assertions are valid for.
   */
  public function setExpiry($expiry)
  {
    $this->expiry = $expiry;
  }

  /**
   * Gets the lifetime of the access token in seconds.
   */
  public function getExpiresIn()
  {
    return $this->expiresIn;
  }

  /**
   * Sets the lifetime of the access token in seconds.
   */
  public function setExpiresIn($expiresIn)
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
   */
  public function getExpiresAt()
  {
    if (!is_null($this->expiresAt)) {
      return $this->expiresAt;
    } else if (!is_null($this->issuedAt) && !is_null($this->expiresIn)) {
      return $this->issuedAt + $this->expiresIn;
    }
    return null;
  }

  /**
   * Returns true if the acccess token has expired.
   */
  public function isExpired()
  {
    $expiration = $this->getExpiresAt();
    $now = time();
    return (!is_null($expiration) && $now >= $expiration);
  }

  /**
   * Sets the time the current access token expires at.
   */
  public function setExpiresAt($expiresAt)
  {
    $this->expiresAt = $expiresAt;
  }

  /**
   * Gets the time the current access token was issued at.
   */
  public function getIssuedAt()
  {
    return $this->issuedAt;
  }

  /**
   * Sets the time the current access token was issued at.
   */
  public function setIssuedAt($issuedAt)
  {
    $this->issuedAt = $issuedAt;
  }

  /**
   * Gets the current access token.
   */
  public function getAccessToken()
  {
    return $this->accessToken;
  }

  /**
   * Sets the current access token.
   */
  public function setAccessToken($accessToken)
  {
    $this->accessToken = $accessToken;
  }

  /**
   * Gets the current ID token.
   */
  public function getIdToken()
  {
    return $this->idToken;
  }

  /**
   * Sets the current ID token.
   */
  public function setIdToken($idToken)
  {
    $this->idToken = $idToken;
  }

  /**
   * Gets the refresh token associated with the current access token.
   */
  public function getRefreshToken()
  {
    return $this->refreshToken;
  }

  /**
   * Sets the refresh token associated with the current access token.
   */
  public function setRefreshToken($refreshToken)
  {
    $this->refreshToken = $refreshToken;
  }

  private function coerceUri($uri)
  {
    if (is_null($uri)) {
      return null;
    } else if (is_string($uri)) {
      return Url::fromString($uri);
    } else if (is_array($uri)) {
      return Url::buildUrl($uri);
    } else if (get_class($uri) == 'GuzzleHttp\Url') {
      return $uri;
    } else {
      throw new \InvalidArgumentException(
          'unexpected type for a uri: ' . get_class($uri));
    }
  }

  /**
   * Determines if the URI is absolute based on its scheme and host or path
   * (RFC 3986)
   */
  private function isAbsoluteUri($u)
  {
    return $u->getScheme() && ($u->getHost() || $u->getPath());
  }

  private function addClientCredentials(&$params)
  {
    $clientId = $this->getClientId();
    $clientSecret = $this->getClientSecret();

    if ($clientId && $clientSecret) {
      $params['client_id'] = $clientId;
      $params['client_secret'] = $clientSecret;
    }

    return $params;
  }
}
