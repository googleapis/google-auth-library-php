<?php
/*
 * Copyright 2010 Google Inc.
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

namespace Google\Auth\Tests;

use DomainException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Google\Auth\ExternalAccountCredentialSourceInterface;
use Google\Auth\OAuth2;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use UnexpectedValueException;

class OAuth2Test extends TestCase
{
    private $minimal = [
        'authorizationUri' => 'https://accounts.test.org/insecure/url',
        'redirectUri' => 'https://accounts.test.org/redirect/url',
        'clientId' => 'aClientID',
    ];

    private $signingMinimal = [
        'signingKey' => 'example_key',
        'signingAlgorithm' => 'HS256',
        'scope' => 'https://www.googleapis.com/auth/userinfo.profile',
        'issuer' => 'app@example.com',
        'audience' => 'accounts.google.com',
        'clientId' => 'aClientID',
    ];

    private $tokenRequestMinimal = [
        'tokenCredentialUri' => 'https://tokens_r_us/test',
        'scope' => 'https://www.googleapis.com/auth/userinfo.profile',
        'issuer' => 'app@example.com',
        'audience' => 'accounts.google.com',
        'clientId' => 'aClientID',
    ];

    private $fetchAuthTokenMinimal = [
        'tokenCredentialUri' => 'https://tokens_r_us/test',
        'scope' => 'https://www.googleapis.com/auth/userinfo.profile',
        'signingKey' => 'example_key',
        'signingAlgorithm' => 'HS256',
        'issuer' => 'app@example.com',
        'audience' => 'accounts.google.com',
        'clientId' => 'aClientID',
    ];

    private $verifyIdTokenMinimal = [
        'scope' => 'https://www.googleapis.com/auth/userinfo.profile',
        'audience' => 'myaccount.on.host.issuer.com',
        'issuer' => 'an.issuer.com',
        'clientId' => 'myaccount.on.host.issuer.com',
    ];

    /**
     * @group oauth2-authorization-uri
     */
    public function testIsNullIfAuthorizationUriIsNull()
    {
        $this->expectException(InvalidArgumentException::class);

        $o = new OAuth2([]);
        $this->assertNull($o->buildFullAuthorizationUri());
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testRequiresTheClientId()
    {
        $this->expectException(InvalidArgumentException::class);

        $o = new OAuth2([
            'authorizationUri' => 'https://accounts.test.org/auth/url',
            'redirectUri' => 'https://accounts.test.org/redirect/url',
        ]);
        $o->buildFullAuthorizationUri();
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testRequiresTheRedirectUri()
    {
        $this->expectException(InvalidArgumentException::class);

        $o = new OAuth2([
            'authorizationUri' => 'https://accounts.test.org/auth/url',
            'clientId' => 'aClientID',
        ]);
        $o->buildFullAuthorizationUri();
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testCannotHavePromptAndApprovalPrompt()
    {
        $this->expectException(InvalidArgumentException::class);

        $o = new OAuth2([
            'authorizationUri' => 'https://accounts.test.org/auth/url',
            'clientId' => 'aClientID',
        ]);
        $o->buildFullAuthorizationUri([
            'approval_prompt' => 'an approval prompt',
            'prompt' => 'a prompt',
        ]);
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testCannotHaveInsecureAuthorizationUri()
    {
        $this->expectException(InvalidArgumentException::class);

        $o = new OAuth2([
            'authorizationUri' => 'http://accounts.test.org/insecure/url',
            'redirectUri' => 'https://accounts.test.org/redirect/url',
            'clientId' => 'aClientID',
        ]);
        $o->buildFullAuthorizationUri();
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testCannotHaveRelativeRedirectUri()
    {
        $this->expectException(InvalidArgumentException::class);

        $o = new OAuth2([
            'authorizationUri' => 'http://accounts.test.org/insecure/url',
            'redirectUri' => '/redirect/url',
            'clientId' => 'aClientID',
        ]);
        $o->buildFullAuthorizationUri();
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testAudOrScopeIsRequiredForJwt()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('one of scope or aud should not be null');
        $o = new OAuth2([]);
        $o->setSigningKey('a key');
        $o->setSigningAlgorithm('RS256');
        $o->setIssuer('an issuer');
        $o->toJwt();
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testHasDefaultXXXTypeParams()
    {
        $o = new OAuth2($this->minimal);
        $q = Query::parse($o->buildFullAuthorizationUri()->getQuery());
        $this->assertEquals('code', $q['response_type']);
        $this->assertEquals('offline', $q['access_type']);
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testCanBeUrlObject()
    {
        $config = array_merge($this->minimal, [
            'authorizationUri' => Utils::uriFor('https://another/uri'),
        ]);
        $o = new OAuth2($config);
        $this->assertEquals('/uri', $o->buildFullAuthorizationUri()->getPath());
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testCanOverrideParams()
    {
        $overrides = [
            'access_type' => 'o_access_type',
            'client_id' => 'o_client_id',
            'redirect_uri' => 'o_redirect_uri',
            'response_type' => 'o_response_type',
            'state' => 'o_state',
        ];
        $config = array_merge($this->minimal, ['state' => 'the_state']);
        $o = new OAuth2($config);
        $q = Query::parse($o->buildFullAuthorizationUri($overrides)->getQuery());
        $this->assertEquals('o_access_type', $q['access_type']);
        $this->assertEquals('o_client_id', $q['client_id']);
        $this->assertEquals('o_redirect_uri', $q['redirect_uri']);
        $this->assertEquals('o_response_type', $q['response_type']);
        $this->assertEquals('o_state', $q['state']);
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testAuthorizationUriWithCodeVerifier()
    {
        $codeVerifier = 'my_code_verifier';
        $expectedCodeChallenge = 'DLIjHQaEUYlb3dD1s35ERX1uDg0eu3_9ggFsQayed5c';

        // test in constructor
        $config = array_merge($this->minimal, ['codeVerifier' => $codeVerifier]);
        $o = new OAuth2($config);
        $q = Query::parse($o->buildFullAuthorizationUri()->getQuery());
        $this->assertArrayNotHasKey('code_verifier', $q);
        $this->assertArrayHasKey('code_challenge', $q);
        $this->assertEquals($expectedCodeChallenge, $q['code_challenge']);
        $this->assertEquals('S256', $q['code_challenge_method']);

        // test in settter
        $o = new OAuth2($this->minimal);
        $o->setCodeVerifier($codeVerifier);
        $q = Query::parse($o->buildFullAuthorizationUri()->getQuery());
        $this->assertArrayNotHasKey('code_verifier', $q);
        $this->assertArrayHasKey('code_challenge', $q);
        $this->assertEquals($expectedCodeChallenge, $q['code_challenge']);
        $this->assertEquals('S256', $q['code_challenge_method']);
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testGenerateCodeVerifier()
    {
        $o = new OAuth2($this->minimal);
        $codeVerifier = $o->generateCodeVerifier();
        $this->assertEquals(128, strlen($codeVerifier));
        // The generated code verifier is set on the object
        $this->assertEquals($o->getCodeVerifier(), $codeVerifier);
        // When it's called again, it generates a new one
        $this->assertNotEquals($codeVerifier, $o->generateCodeVerifier());
        // The new code verifier is set on the object
        $this->assertNotEquals($codeVerifier, $o->getCodeVerifier());
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testIncludesTheScope()
    {
        $with_strings = array_merge($this->minimal, ['scope' => 'scope1 scope2']);
        $o = new OAuth2($with_strings);
        $q = Query::parse($o->buildFullAuthorizationUri()->getQuery());
        $this->assertEquals('scope1 scope2', $q['scope']);

        $with_array = array_merge($this->minimal, [
            'scope' => ['scope1', 'scope2'],
        ]);
        $o = new OAuth2($with_array);
        $q = Query::parse($o->buildFullAuthorizationUri()->getQuery());
        $this->assertEquals('scope1 scope2', $q['scope']);
    }

    /**
     * @group oauth2-authorization-uri
     */
    public function testRedirectUriPostmessageIsAllowed()
    {
        $o = new OAuth2([
            'authorizationUri' => 'https://accounts.test.org/insecure/url',
            'redirectUri' => 'postmessage',
            'clientId' => 'aClientID',
        ]);
        $this->assertEquals('postmessage', $o->getRedirectUri());
        $url = $o->buildFullAuthorizationUri();
        $parts = parse_url((string)$url);
        parse_str($parts['query'], $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertEquals('postmessage', $query['redirect_uri']);
    }

    /**
     * @group oauth2-grant-type
     */
    public function testReturnsNullIfCannotBeInferred()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getGrantType());
    }

    /**
     * @group oauth2-grant-type
     */
    public function testInfersAuthorizationCode()
    {
        $o = new OAuth2($this->minimal);
        $o->setCode('an auth code');
        $this->assertEquals('authorization_code', $o->getGrantType());
    }

    /**
     * @group oauth2-grant-type
     */
    public function testInfersRefreshToken()
    {
        $o = new OAuth2($this->minimal);
        $o->setRefreshToken('a refresh token');
        $this->assertEquals('refresh_token', $o->getGrantType());
    }

    /**
     * @group oauth2-grant-type
     */
    public function testInfersPassword()
    {
        $o = new OAuth2($this->minimal);
        $o->setPassword('a password');
        $o->setUsername('a username');
        $this->assertEquals('password', $o->getGrantType());
    }

    /**
     * @group oauth2-grant-type
     */
    public function testInfersJwtBearer()
    {
        $o = new OAuth2($this->minimal);
        $o->setIssuer('an issuer');
        $o->setSigningKey('a key');
        $this->assertEquals(
            'urn:ietf:params:oauth:grant-type:jwt-bearer',
            $o->getGrantType()
        );
    }

    /**
     * @group oauth2-grant-type
     */
    public function testSetsKnownTypes()
    {
        $o = new OAuth2($this->minimal);
        foreach (OAuth2::$knownGrantTypes as $t) {
            $o->setGrantType($t);
            $this->assertEquals($t, $o->getGrantType());
        }
    }

    /**
     * @group oauth2-grant-type
     */
    public function testSetsUrlAsGrantType()
    {
        $o = new OAuth2($this->minimal);
        $o->setGrantType('http://a/grant/url');
        $this->assertEquals('http://a/grant/url', $o->getGrantType());
    }

    /**
     * @group oauth2-cache-key
     */
    public function testIsNullWithNoScopesOrAudience()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getCacheKey());
    }

    /**
     * @group oauth2-cache-key
     */
    public function testIsScopeIfSingleScope()
    {
        $o = new OAuth2($this->minimal);
        $o->setScope('test/scope/1');
        $this->assertEquals('test/scope/1', $o->getCacheKey());
    }

    /**
     * @group oauth2-cache-key
     */
    public function testIsAllScopesWhenScopeIsArray()
    {
        $o = new OAuth2($this->minimal);
        $o->setScope(['test/scope/1', 'test/scope/2']);
        $this->assertEquals('test/scope/1:test/scope/2', $o->getCacheKey());
    }

    /**
     * @group oauth2-cache-key
     */
    public function testIsAudienceWhenScopeIsNull()
    {
        $aud = 'https://drive.googleapis.com';
        $o = new OAuth2($this->minimal);
        $o->setAudience($aud);
        $this->assertEquals($aud, $o->getCacheKey());
    }

    /**
     * @group oauth2-timing
     */
    public function testIssuedAtDefaultsToNull()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getIssuedAt());
    }

    /**
     * @group oauth2-timing
     */
    public function testExpiresAtDefaultsToNull()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getExpiresAt());
    }

    /**
     * @group oauth2-timing
     */
    public function testExpiresInDefaultsToNull()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getExpiresIn());
    }

    /**
     * @group oauth2-timing
     */
    public function testSettingExpiresInSetsIssuedAt()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getIssuedAt());
        $aShortWhile = 5;
        $o->setExpiresIn($aShortWhile);
        $this->assertEquals($aShortWhile, $o->getExpiresIn());
        $this->assertNotNull($o->getIssuedAt());
    }

    /**
     * @group oauth2-timing
     */
    public function testSettingExpiresInSetsExpireAt()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getExpiresAt());
        $aShortWhile = 5;
        $o->setExpiresIn($aShortWhile);
        $this->assertNotNull($o->getExpiresAt());
        $this->assertEquals($aShortWhile, $o->getExpiresAt() - $o->getIssuedAt());
    }

    /**
     * @group oauth2-timing
     */
    public function testIsNotExpiredByDefault()
    {
        $o = new OAuth2($this->minimal);
        $this->assertFalse($o->isExpired());
    }

    /**
     * @group oauth2-timing
     */
    public function testIsNotExpiredIfExpiresAtIsOld()
    {
        $o = new OAuth2($this->minimal);
        $o->setExpiresAt(time() - 2);
        $this->assertTrue($o->isExpired());
    }

    /**
     * @group oauth2-general
     */
    public function testFailsOnUnknownSigningAlgorithm()
    {
        $this->expectException(InvalidArgumentException::class);

        $o = new OAuth2($this->minimal);
        $o->setSigningAlgorithm('this is definitely not an algorithm name');
    }

    /**
     * @group oauth2-general
     */
    public function testAllowsKnownSigningAlgorithms()
    {
        $o = new OAuth2($this->minimal);
        foreach (OAuth2::$knownSigningAlgorithms as $a) {
            $o->setSigningAlgorithm($a);
            $this->assertEquals($a, $o->getSigningAlgorithm());
        }
    }

    /**
     * @group oauth2-general
     */
    public function testFailsOnRelativeRedirectUri()
    {
        $this->expectException(InvalidArgumentException::class);

        $o = new OAuth2($this->minimal);
        $o->setRedirectUri('/relative/url');
    }

    /**
     * @group oauth2-general
     */
    public function testAllowsUrnRedirectUri()
    {
        $urn = 'urn:ietf:wg:oauth:2.0:oob';
        $o = new OAuth2($this->minimal);
        $o->setRedirectUri($urn);
        $this->assertEquals($urn, $o->getRedirectUri());
    }

    /**
     * @group oauth2-jwt
     */
    public function testFailsWithMissingAudience()
    {
        $this->expectException(DomainException::class);
        $testConfig = $this->signingMinimal;
        unset($testConfig['audience']);
        unset($testConfig['scope']);
        $o = new OAuth2($testConfig);
        $o->toJwt();
    }

    /**
     * @group oauth2-jwt
     */
    public function testFailsWithMissingIssuer()
    {
        $this->expectException(DomainException::class);
        $testConfig = $this->signingMinimal;
        unset($testConfig['issuer']);
        $o = new OAuth2($testConfig);
        $o->toJwt();
    }

    /**
     * @group oauth2-jwt
     */
    public function testCanHaveNoScope()
    {
        $testConfig = $this->signingMinimal;
        unset($testConfig['scope']);
        $o = new OAuth2($testConfig);
        $jwt = $o->toJwt();
        $this->assertTrue(is_string($jwt));
    }

    /**
     * @group oauth2-jwt
     */
    public function testFailsWithMissingSigningKey()
    {
        $this->expectException(DomainException::class);

        $testConfig = $this->signingMinimal;
        unset($testConfig['signingKey']);
        $o = new OAuth2($testConfig);
        $o->toJwt();
    }

    /**
     * @group oauth2-jwt
     */
    public function testFailsWithMissingSigningAlgorithm()
    {
        $this->expectException(DomainException::class);
        $testConfig = $this->signingMinimal;
        unset($testConfig['signingAlgorithm']);
        $o = new OAuth2($testConfig);
        $o->toJwt();
    }

    /**
     * @group oauth2-jwt
     */
    public function testCanHS256EncodeAValidPayloadWithSigningKeyId()
    {
        $testConfig = $this->signingMinimal;
        $keys = [
            'example_key_id1' => new Key('example_key1', 'HS256'),
            'example_key_id2' => new Key('example_key2', 'HS256'),
        ];
        $testConfig['signingKey'] = $keys['example_key_id2']->getKeyMaterial();
        $testConfig['signingKeyId'] = 'example_key_id2';
        $o = new OAuth2($testConfig);
        $payload = $o->toJwt();
        $roundTrip = JWT::decode($payload, $keys);
        $this->assertEquals($roundTrip->iss, $testConfig['issuer']);
        $this->assertEquals($roundTrip->aud, $testConfig['audience']);
        $this->assertEquals($roundTrip->scope, $testConfig['scope']);
    }

    /**
     * @group oauth2-jwt
     */
    public function testFailDecodeWithoutSigningKeyId()
    {
        $testConfig = $this->signingMinimal;
        $keys = [
            'example_key_id1' => new Key('example_key1', 'HS256'),
            'example_key_id2' => new Key('example_key2', 'HS256'),
        ];
        $testConfig['signingKey'] = $keys['example_key_id2']->getKeyMaterial();
        $o = new OAuth2($testConfig);
        $payload = $o->toJwt();

        try {
            JWT::decode($payload, $keys);
        } catch (\Exception $e) {
            // Workaround: In old JWT versions throws DomainException
            $this->assertTrue(
                ($e instanceof \DomainException || $e instanceof \UnexpectedValueException)
                && $e->getMessage() === '"kid" empty, unable to lookup correct key'
            );
            return;
        }
        $this->fail('Expected exception about problem with decode');
    }

    /**
     * @group oauth2-jwt
     */
    public function testCanHS256EncodeAValidPayload()
    {
        $testConfig = $this->signingMinimal;
        $o = new OAuth2($testConfig);
        $payload = $o->toJwt();
        $roundTrip = JWT::decode($payload, new Key($testConfig['signingKey'], 'HS256'));
        $this->assertEquals($roundTrip->iss, $testConfig['issuer']);
        $this->assertEquals($roundTrip->aud, $testConfig['audience']);
        $this->assertEquals($roundTrip->scope, $testConfig['scope']);
    }

    /**
     * @group oauth2-jwt
     */
    public function testCanRS256EncodeAValidPayload()
    {
        $publicKey = file_get_contents(__DIR__ . '/fixtures' . '/public.pem');
        $privateKey = file_get_contents(__DIR__ . '/fixtures' . '/private.pem');
        $testConfig = $this->signingMinimal;
        $o = new OAuth2($testConfig);
        $o->setSigningAlgorithm('RS256');
        $o->setSigningKey($privateKey);
        $payload = $o->toJwt();
        $roundTrip = JWT::decode($payload, new Key($publicKey, 'RS256'));
        $this->assertEquals($roundTrip->iss, $testConfig['issuer']);
        $this->assertEquals($roundTrip->aud, $testConfig['audience']);
        $this->assertEquals($roundTrip->scope, $testConfig['scope']);
    }

    /**
     * @group oauth2-jwt
     */
    public function testCanHaveAdditionalClaims()
    {
        $publicKey = file_get_contents(__DIR__ . '/fixtures' . '/public.pem');
        $privateKey = file_get_contents(__DIR__ . '/fixtures' . '/private.pem');
        $testConfig = $this->signingMinimal;
        $targetAud = '123@456.com';
        $testConfig['additionalClaims'] = ['target_audience' => $targetAud];
        $o = new OAuth2($testConfig);
        $o->setSigningAlgorithm('RS256');
        $o->setSigningKey($privateKey);
        $payload = $o->toJwt();
        $roundTrip = JWT::decode($payload, new Key($publicKey, 'RS256'));
        $this->assertEquals($roundTrip->target_audience, $targetAud);
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testFailsIfNoTokenCredentialUri()
    {
        $this->expectException(DomainException::class);
        $testConfig = $this->tokenRequestMinimal;
        unset($testConfig['tokenCredentialUri']);
        $o = new OAuth2($testConfig);
        $o->generateCredentialsRequest();
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testFailsIfAuthorizationCodeIsMissing()
    {
        $this->expectException(DomainException::class);
        $testConfig = $this->tokenRequestMinimal;
        $testConfig['redirectUri'] = 'https://has/redirect/uri';
        $o = new OAuth2($testConfig);
        $o->generateCredentialsRequest();
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testGeneratesAuthorizationCodeRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $testConfig['redirectUri'] = 'https://has/redirect/uri';
        $o = new OAuth2($testConfig);
        $o->setCode('an_auth_code');

        // Generate the request and confirm that it's correct.
        $req = $o->generateCredentialsRequest();
        $this->assertInstanceOf('Psr\Http\Message\RequestInterface', $req);
        $this->assertEquals('POST', $req->getMethod());
        $fields = Query::parse((string)$req->getBody());
        $this->assertEquals('authorization_code', $fields['grant_type']);
        $this->assertEquals('an_auth_code', $fields['code']);
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testGeneratesPasswordRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $o = new OAuth2($testConfig);
        $o->setUsername('a_username');
        $o->setPassword('a_password');

        // Generate the request and confirm that it's correct.
        $req = $o->generateCredentialsRequest();
        $this->assertInstanceOf('Psr\Http\Message\RequestInterface', $req);
        $this->assertEquals('POST', $req->getMethod());
        $fields = Query::parse((string)$req->getBody());
        $this->assertEquals('password', $fields['grant_type']);
        $this->assertEquals('a_password', $fields['password']);
        $this->assertEquals('a_username', $fields['username']);
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testGeneratesRefreshTokenRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $o = new OAuth2($testConfig);
        $o->setRefreshToken('a_refresh_token');

        // Generate the request and confirm that it's correct.
        $req = $o->generateCredentialsRequest();
        $this->assertInstanceOf('Psr\Http\Message\RequestInterface', $req);
        $this->assertEquals('POST', $req->getMethod());
        $fields = Query::parse((string)$req->getBody());
        $this->assertEquals('refresh_token', $fields['grant_type']);
        $this->assertEquals('a_refresh_token', $fields['refresh_token']);
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testClientSecretAddedIfSetForAuthorizationCodeRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $testConfig['clientSecret'] = 'a_client_secret';
        $testConfig['redirectUri'] = 'https://has/redirect/uri';
        $o = new OAuth2($testConfig);
        $o->setCode('an_auth_code');
        $request = $o->generateCredentialsRequest();
        $fields = Query::parse((string)$request->getBody());
        $this->assertEquals('a_client_secret', $fields['client_secret']);
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testClientSecretAddedIfSetForRefreshTokenRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $testConfig['clientSecret'] = 'a_client_secret';
        $o = new OAuth2($testConfig);
        $o->setRefreshToken('a_refresh_token');
        $request = $o->generateCredentialsRequest();
        $fields = Query::parse((string)$request->getBody());
        $this->assertEquals('a_client_secret', $fields['client_secret']);
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testClientSecretAddedIfSetForPasswordRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $testConfig['clientSecret'] = 'a_client_secret';
        $o = new OAuth2($testConfig);
        $o->setUsername('a_username');
        $o->setPassword('a_password');
        $request = $o->generateCredentialsRequest();
        $fields = Query::parse((string)$request->getBody());
        $this->assertEquals('a_client_secret', $fields['client_secret']);
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testGeneratesAssertionRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $o = new OAuth2($testConfig);
        $o->setSigningKey('a_key');
        $o->setSigningAlgorithm('HS256');

        // Generate the request and confirm that it's correct.
        $req = $o->generateCredentialsRequest();
        $this->assertInstanceOf('Psr\Http\Message\RequestInterface', $req);
        $this->assertEquals('POST', $req->getMethod());
        $fields = Query::parse((string)$req->getBody());
        $this->assertEquals(OAuth2::JWT_URN, $fields['grant_type']);
        $this->assertArrayHasKey('assertion', $fields);
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testGeneratesExtendedRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $o = new OAuth2($testConfig);
        $o->setGrantType('urn:my_test_grant_type');
        $o->setExtensionParams(['my_param' => 'my_value']);

        // Generate the request and confirm that it's correct.
        $req = $o->generateCredentialsRequest();
        $this->assertInstanceOf('Psr\Http\Message\RequestInterface', $req);
        $this->assertEquals('POST', $req->getMethod());
        $fields = Query::parse((string)$req->getBody());
        $this->assertEquals('my_value', $fields['my_param']);
        $this->assertEquals('urn:my_test_grant_type', $fields['grant_type']);
    }

    /**
     * @group oauth2-generate-access-token
     */
    public function testTokenUriWithCodeVerifier()
    {
        $codeVerifier = 'my_code_verifier';

        // test in constructor
        $config = array_merge($this->tokenRequestMinimal, [
            'codeVerifier' => $codeVerifier,
        ]);
        $o = new OAuth2($config);
        $o->setCode('abc123');
        $req = $o->generateCredentialsRequest();
        $fields = Query::parse((string) $req->getBody());
        $this->assertArrayHasKey('code_verifier', $fields);
        $this->assertEquals($codeVerifier, $fields['code_verifier']);

        // test in settter
        $o = new OAuth2($this->tokenRequestMinimal);
        $o->setCode('abc123');
        $o->setCodeVerifier($codeVerifier);
        $req = $o->generateCredentialsRequest();
        $q = Query::parse((string) $req->getBody());
        $this->assertArrayHasKey('code_verifier', $q);
        $this->assertEquals($codeVerifier, $q['code_verifier']);
    }

    /**
     * @group oauth2-fetch-auth-token
     */
    public function testFailsOn400()
    {
        $this->expectException(\GuzzleHttp\Exception\ClientException::class);

        $testConfig = $this->fetchAuthTokenMinimal;
        $httpHandler = getHandler([
            new Response(400),
        ]);
        $o = new OAuth2($testConfig);
        $o->fetchAuthToken($httpHandler);
    }

    /**
     * @group oauth2-fetch-auth-token
     */
    public function testFailsOn500()
    {
        $this->expectException(\GuzzleHttp\Exception\ServerException::class);

        $testConfig = $this->fetchAuthTokenMinimal;
        $httpHandler = getHandler([
            new Response(500),
        ]);
        $o = new OAuth2($testConfig);
        $o->fetchAuthToken($httpHandler);
    }

    /**
     * @group oauth2-fetch-auth-token
     */
    public function testFailsOnNoContentTypeIfResponseIsNotJSON()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid JSON response');

        $testConfig = $this->fetchAuthTokenMinimal;
        $notJson = '{"foo": , this is cannot be passed as json" "bar"}';
        $httpHandler = getHandler([
            new Response(200, [], Utils::streamFor($notJson)),
        ]);
        $o = new OAuth2($testConfig);
        $o->fetchAuthToken($httpHandler);
    }

    /**
     * @group oauth2-fetch-auth-token
     */
    public function testFetchesJsonResponseOnNoContentTypeOK()
    {
        $testConfig = $this->fetchAuthTokenMinimal;
        $json = '{"foo": "bar"}';
        $httpHandler = getHandler([
            new Response(200, [], Utils::streamFor($json)),
        ]);
        $o = new OAuth2($testConfig);
        $tokens = $o->fetchAuthToken($httpHandler);
        $this->assertEquals($tokens['foo'], 'bar');
    }

    /**
     * @group oauth2-fetch-auth-token
     */
    public function testFetchesFromFormEncodedResponseOK()
    {
        $testConfig = $this->fetchAuthTokenMinimal;
        $json = 'foo=bar&spice=nice';
        $httpHandler = getHandler([
            new Response(
                200,
                ['Content-Type' => 'application/x-www-form-urlencoded'],
                Utils::streamFor($json)
            ),
        ]);
        $o = new OAuth2($testConfig);
        $tokens = $o->fetchAuthToken($httpHandler);
        $this->assertEquals($tokens['foo'], 'bar');
        $this->assertEquals($tokens['spice'], 'nice');
    }

    /**
     * @group oauth2-fetch-auth-token
     */
    public function testUpdatesTokenFieldsOnFetch()
    {
        $testConfig = $this->fetchAuthTokenMinimal;
        $wanted_updates = [
            'expires_at' => '1',
            'expires_in' => '57',
            'issued_at' => '2',
            'access_token' => 'an_access_token',
            'id_token' => 'an_id_token',
            'refresh_token' => 'a_refresh_token',
            'scope' => 'scope1 scope2',
        ];
        $json = json_encode($wanted_updates);
        $httpHandler = getHandler([
            new Response(200, [], Utils::streamFor($json)),
        ]);
        $o = new OAuth2($testConfig);
        $this->assertNull($o->getExpiresAt());
        $this->assertNull($o->getExpiresIn());
        $this->assertNull($o->getIssuedAt());
        $this->assertNull($o->getAccessToken());
        $this->assertNull($o->getIdToken());
        $this->assertNull($o->getRefreshToken());
        $tokens = $o->fetchAuthToken($httpHandler);
        $this->assertEquals(1, $o->getExpiresAt());
        $this->assertEquals(57, $o->getExpiresIn());
        $this->assertEquals(2, $o->getIssuedAt());
        $this->assertEquals('an_access_token', $o->getAccessToken());
        $this->assertEquals('an_id_token', $o->getIdToken());
        $this->assertEquals('a_refresh_token', $o->getRefreshToken());
        $this->assertEquals('scope1 scope2', $o->getGrantedScope());
    }

    /**
     * @group oauth2-fetch-auth-token
     */
    public function testUpdatesTokenFieldsOnFetchMissingRefreshToken()
    {
        $testConfig = $this->fetchAuthTokenMinimal;
        $testConfig['refresh_token'] = 'a_refresh_token';
        $wanted_updates = [
            'expires_at' => '1',
            'expires_in' => '57',
            'issued_at' => '2',
            'access_token' => 'an_access_token',
            'id_token' => 'an_id_token',
        ];
        $json = json_encode($wanted_updates);
        $httpHandler = getHandler([
            new Response(200, [], Utils::streamFor($json)),
        ]);
        $o = new OAuth2($testConfig);
        $this->assertNull($o->getExpiresAt());
        $this->assertNull($o->getExpiresIn());
        $this->assertNull($o->getIssuedAt());
        $this->assertNull($o->getAccessToken());
        $this->assertNull($o->getIdToken());
        $this->assertEquals('a_refresh_token', $o->getRefreshToken());
        $tokens = $o->fetchAuthToken($httpHandler);
        $this->assertEquals(1, $o->getExpiresAt());
        $this->assertEquals(57, $o->getExpiresIn());
        $this->assertEquals(2, $o->getIssuedAt());
        $this->assertEquals('an_access_token', $o->getAccessToken());
        $this->assertEquals('an_id_token', $o->getIdToken());
        $this->assertEquals('a_refresh_token', $o->getRefreshToken());
    }

    /**
     * @dataProvider provideGetLastReceivedToken
     * @group oauth2-fetch-auth-token
     */
    public function testGetLastReceivedToken(
        $updateToken,
        $expectedToken = null
    ) {
        $testConfig = $this->fetchAuthTokenMinimal;
        $o = new OAuth2($testConfig);
        $o->updateToken($updateToken);
        $this->assertEquals(
            $expectedToken ?: $updateToken,
            $o->getLastReceivedToken()
        );
    }

    public function provideGetLastReceivedToken()
    {
        $time = time();
        return [
            [
                ['access_token' => 'abc'],
                ['access_token' => 'abc', 'expires_at' => null],
            ],
            [
                ['access_token' => 'abc', 'invalid-field' => 'foo'],
                ['access_token' => 'abc', 'expires_at' => null],
            ],
            [
                ['access_token' => 'abc', 'expires_at' => 1234567890],
                ['access_token' => 'abc', 'expires_at' => 1234567890],
            ],
            [
                ['id_token' => 'def'],
                ['id_token' => 'def', 'expires_at' => null],
            ],
            [
                ['id_token' => 'def', 'expires_at' => 1234567890],
                ['id_token' => 'def', 'expires_at' => 1234567890],
            ],
            [
                [
                    'access_token' => 'abc',
                    'expires_in' => 3600,
                    'issued_at' => $time
                ],
                [
                    'access_token' => 'abc',
                    'expires_at' => $time + 3600,
                    'expires_in' => 3600,
                    'issued_at' => $time
                ],
            ],
            [
                ['access_token' => 'abc', 'issued_at' => 1234567890],
                [
                    'access_token' => 'abc',
                    'expires_at' => null,
                    'issued_at' => 1234567890
                ],
            ],
            [
                ['access_token' => 'abc', 'refresh_token' => 'xyz'],
                [
                    'access_token' => 'abc',
                    'expires_at' => null,
                    'refresh_token' => 'xyz'
                ],
            ],
        ];
    }

    /**
     * @group oauth2-verify-id-token
     */
    public function testFailsIfIdTokenIsInvalid()
    {
        $this->expectException(UnexpectedValueException::class);

        $publicKey = file_get_contents(__DIR__ . '/fixtures' . '/public.pem');
        $testConfig = $this->verifyIdTokenMinimal;
        $not_a_jwt = 'not a jot';
        $o = new OAuth2($testConfig);
        $o->setIdToken($not_a_jwt);
        $o->verifyIdToken($publicKey, ['RS256']);
    }

    /**
     * @group oauth2-verify-id-token
     */
    public function testFailsIfAudienceIsMissing()
    {
        $this->expectException(DomainException::class);

        $publicKey = file_get_contents(__DIR__ . '/fixtures' . '/public.pem');
        $privateKey = file_get_contents(__DIR__ . '/fixtures' . '/private.pem');
        $testConfig = $this->verifyIdTokenMinimal;
        $now = time();
        $origIdToken = [
            'issuer' => $testConfig['issuer'],
            'exp' => $now + 65, // arbitrary
            'iat' => $now,
        ];
        $o = new OAuth2($testConfig);
        $jwtIdToken = JWT::encode($origIdToken, $privateKey, 'RS256');
        $o->setIdToken($jwtIdToken);
        $o->verifyIdToken($publicKey, ['RS256']);
    }

    /**
     * @group oauth2-verify-id-token
     */
    public function testFailsIfAudienceIsWrong()
    {
        $this->expectException(DomainException::class);

        $publicKey = file_get_contents(__DIR__ . '/fixtures' . '/public.pem');
        $privateKey = file_get_contents(__DIR__ . '/fixtures' . '/private.pem');
        $now = time();
        $testConfig = $this->verifyIdTokenMinimal;
        $origIdToken = [
            'aud' => 'a different audience',
            'iss' => $testConfig['issuer'],
            'exp' => $now + 65, // arbitrary
            'iat' => $now,
        ];
        $o = new OAuth2($testConfig);
        $jwtIdToken = JWT::encode($origIdToken, $privateKey, 'RS256');
        $o->setIdToken($jwtIdToken);
        $o->verifyIdToken($publicKey, ['RS256']);
    }

    /**
     * @group oauth2-verify-id-token
     */
    public function testFailsWithStringPublicKeyAndAllowedAlgsGreaterThanOne()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('To have multiple allowed algorithms');

        $publicKey = file_get_contents(__DIR__ . '/fixtures' . '/public.pem');
        $testConfig = $this->verifyIdTokenMinimal;
        $not_a_jwt = 'not a jot';
        $o = new OAuth2($testConfig);
        $o->setIdToken($not_a_jwt);
        $o->verifyIdToken($publicKey, ['RS256', 'ES256']);
    }

    /**
     * @group oauth2-verify-id-token
     */
    public function testFailsWithStringPublicKeyAndNoAllowedAlgs()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('When allowed algorithms is empty');

        $publicKey = file_get_contents(__DIR__ . '/fixtures' . '/public.pem');
        $testConfig = $this->verifyIdTokenMinimal;
        $not_a_jwt = 'not a jot';
        $o = new OAuth2($testConfig);
        $o->setIdToken($not_a_jwt);
        $o->verifyIdToken($publicKey, []);
    }

    /**
     * @group oauth2-verify-id-token
     */
    public function testFailsWithStringInPublicKeyArrayAndNoAllowedAlgs()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('When allowed algorithms is empty');

        $publicKey = file_get_contents(__DIR__ . '/fixtures' . '/public.pem');
        $testConfig = $this->verifyIdTokenMinimal;
        $not_a_jwt = 'not a jot';
        $o = new OAuth2($testConfig);
        $o->setIdToken($not_a_jwt);
        $o->verifyIdToken([
            new Key($publicKey, 'RS256'),
            $publicKey,
        ], []);
    }

    /**
     * @group oauth2-verify-id-token
     */
    public function testFailsWithInvalidTypeForAllowedAlgs()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('allowed algorithms must be a string or array');

        $publicKey = file_get_contents(__DIR__ . '/fixtures' . '/public.pem');
        $testConfig = $this->verifyIdTokenMinimal;
        $not_a_jwt = 'not a jot';
        $o = new OAuth2($testConfig);
        $o->setIdToken($not_a_jwt);
        $o->verifyIdToken($publicKey, 123);
    }

    /**
     * @group oauth2-verify-id-token
     */
    public function testShouldReturnAValidIdToken()
    {
        $publicKey = file_get_contents(__DIR__ . '/fixtures' . '/public.pem');
        $privateKey = file_get_contents(__DIR__ . '/fixtures' . '/private.pem');
        $testConfig = $this->verifyIdTokenMinimal;
        $now = time();
        $origIdToken = [
            'aud' => $testConfig['audience'],
            'iss' => $testConfig['issuer'],
            'exp' => $now + 65, // arbitrary
            'iat' => $now,
        ];
        $o = new OAuth2($testConfig);
        $alg = 'RS256';
        $jwtIdToken = JWT::encode($origIdToken, $privateKey, $alg);
        $o->setIdToken($jwtIdToken);
        $roundTrip = $o->verifyIdToken($publicKey, [$alg]);
        $this->assertEquals($origIdToken['aud'], $roundTrip->aud);
    }
}

class OAuth2StsTest extends TestCase
{
    use ProphecyTrait;

    private $publicKey;
    private $privateKey;
    private $stsMinimal = [
        'tokenCredentialUri' => 'https://tokens_r_us/test',
        'subjectTokenType' => 'urn:ietf:params:aws:token-type:aws4_request',
    ];

    public function testStsGrantType()
    {
        $credentialSource = $this->prophesize(ExternalAccountCredentialSourceInterface::class);
        $o = new OAuth2($this->stsMinimal + ['subjectTokenFetcher' => $credentialSource->reveal()]);
        $this->assertEquals(OAuth2::STS_URN, $o->getGrantType());
    }

    public function testStsCredentialsRequestMinimal()
    {
        $credentialSource = $this->prophesize(ExternalAccountCredentialSourceInterface::class);
        $credentialSource->fetchSubjectToken(null)
            ->shouldBeCalledOnce()
            ->willReturn('xyz');
        $o = new OAuth2($this->stsMinimal + ['subjectTokenFetcher' => $credentialSource->reveal()]);
        $request = $o->generateCredentialsRequest();
        $this->assertEquals('POST', $request->getMethod());
        $this->assertEquals($this->stsMinimal['tokenCredentialUri'], (string) $request->getUri());
        parse_str((string)$request->getBody(), $requestParams);
        $this->assertCount(4, $requestParams);
        $this->assertEquals(OAuth2::STS_URN, $requestParams['grant_type']);
        $this->assertEquals('xyz', $requestParams['subject_token']);
        $this->assertEquals($this->stsMinimal['subjectTokenType'], $requestParams['subject_token_type']);
    }

    public function testStsCredentialsRequestFull()
    {
        $credentialSource = $this->prophesize(ExternalAccountCredentialSourceInterface::class);
        $credentialSource->fetchSubjectToken(null)
            ->shouldBeCalledOnce()
            ->willReturn('xyz');
        $stsMinimal = $this->stsMinimal + [
            'subjectTokenFetcher' => $credentialSource->reveal(),
            'resource' => 'abc',
            'scope' => ['scope1', 'scope2'],
            'audience' => 'def',
            'actorToken' => '123',
            'actorTokenType' => 'urn:ietf:params:oauth:token-type:access_token',
        ];
        $o = new OAuth2($stsMinimal);
        $request = $o->generateCredentialsRequest();
        $this->assertEquals('POST', $request->getMethod());
        $this->assertEquals($this->stsMinimal['tokenCredentialUri'], (string) $request->getUri());
        parse_str((string)$request->getBody(), $requestParams);

        $this->assertCount(9, $requestParams);
        $this->assertEquals(OAuth2::STS_URN, $requestParams['grant_type']);
        $this->assertEquals('xyz', $requestParams['subject_token']);
        $this->assertEquals($stsMinimal['subjectTokenType'], $requestParams['subject_token_type']);
        $this->assertEquals($stsMinimal['resource'], $requestParams['resource']);
        $this->assertEquals('scope1 scope2', $requestParams['scope']);
        $this->assertEquals($stsMinimal['audience'], $requestParams['audience']);
        $this->assertEquals($stsMinimal['actorToken'], $requestParams['actor_token']);
        $this->assertEquals($stsMinimal['actorTokenType'], $requestParams['actor_token_type']);
    }
}
