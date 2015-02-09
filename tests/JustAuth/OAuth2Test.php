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

use Google\Auth\OAuth2;
use GuzzleHttp\Url;

class OAuth2AuthorizationUriTest extends \PHPUnit_Framework_TestCase
{

  private $minimal = [
      'authorizationUri' => 'https://accounts.test.org/insecure/url',
      'redirectUri' => 'https://accounts.test.org/redirect/url',
      'clientId' => 'aClientID'
  ];

  /**
   * @expectedException InvalidArgumentException
   */
  public function testIsNullIfAuthorizationUriIsNull()
  {
    $o = new OAuth2([]);
    $this->assertNull($o->buildFullAuthorizationUri());
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testRequiresTheClientId()
  {
    $o = new OAuth2([
        'authorizationUri' => 'https://accounts.test.org/auth/url',
        'redirectUri' => 'https://accounts.test.org/redirect/url'
    ]);
    $o->buildFullAuthorizationUri();
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testRequiresTheRedirectUri()
  {
    $o = new OAuth2([
        'authorizationUri' => 'https://accounts.test.org/auth/url',
        'clientId' => 'aClientID'
    ]);
    $o->buildFullAuthorizationUri();
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testCannotHavePromptAndApprovalPrompt()
  {
    $o = new OAuth2([
        'authorizationUri' => 'https://accounts.test.org/auth/url',
        'clientId' => 'aClientID'
    ]);
    $o->buildFullAuthorizationUri([
        'approvalPrompt' => 'an approval prompt',
        'prompt' => 'a prompt',
    ]);
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testCannotHaveInsecureAuthorizationUri()
  {
    $o = new OAuth2([
        'authorizationUri' => 'http://accounts.test.org/insecure/url',
        'redirectUri' => 'https://accounts.test.org/redirect/url',
        'clientId' => 'aClientID'
    ]);
    $o->buildFullAuthorizationUri();
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testCannotHaveRelativeRedirectUri()
  {
    $o = new OAuth2([
        'authorizationUri' => 'http://accounts.test.org/insecure/url',
        'redirectUri' => '/redirect/url',
        'clientId' => 'aClientID'
    ]);
    $o->buildFullAuthorizationUri();
  }

  public function testHasDefaultXXXTypeParams()
  {
    $o = new OAuth2($this->minimal);
    $q = $o->buildFullAuthorizationUri()->getQuery();
    $this->assertEquals('code', $q->get('response_type'));
    $this->assertEquals('offline', $q->get('access_type'));
  }

  public function testCanBeUrlObject()
  {
    $config = array_merge($this->minimal, [
        'authorizationUri' => Url::fromString('https://another/uri')
    ]);
    $o = new OAuth2($config);
    $this->assertEquals('/uri', $o->buildFullAuthorizationUri()->getPath());
  }

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
    $q = $o->buildFullAuthorizationUri($overrides)->getQuery();
    $this->assertEquals('o_access_type', $q->get('access_type'));
    $this->assertEquals('o_client_id', $q->get('client_id'));
    $this->assertEquals('o_redirect_uri', $q->get('redirect_uri'));
    $this->assertEquals('o_response_type', $q->get('response_type'));
    $this->assertEquals('o_state', $q->get('state'));
  }

  public function testIncludesTheScope()
  {
    $with_strings = array_merge($this->minimal, ['scope' => 'scope1 scope2']);
    $o = new OAuth2($with_strings);
    $q = $o->buildFullAuthorizationUri()->getQuery();
    $this->assertEquals('scope1 scope2', $q->get('scope'));

    $with_array = array_merge($this->minimal, [
        'scope' => ['scope1', 'scope2']
    ]);
    $o = new OAuth2($with_array);
    $q = $o->buildFullAuthorizationUri()->getQuery();
    $this->assertEquals('scope1 scope2', $q->get('scope'));
  }

}

class OAuth2GrantTypeTest extends \PHPUnit_Framework_TestCase
{
  private $minimal = [
      'authorizationUri' => 'https://accounts.test.org/insecure/url',
      'redirectUri' => 'https://accounts.test.org/redirect/url',
      'clientId' => 'aClientID'
  ];

  public function testReturnsNullIfCannotBeInferred()
  {
    $o = new OAuth2($this->minimal);
    $this->assertNull($o->getGrantType());
  }

  public function testInfersAuthorizationCode()
  {
    $o = new OAuth2($this->minimal);
    $o->setCode('an auth code');
    $this->assertEquals('authorization_code', $o->getGrantType());
  }

  public function testInfersRefreshToken()
  {
    $o = new OAuth2($this->minimal);
    $o->setRefreshToken('a refresh token');
    $this->assertEquals('refresh_token', $o->getGrantType());
  }

  public function testInfersPassword()
  {
    $o = new OAuth2($this->minimal);
    $o->setPassword('a password');
    $o->setUsername('a username');
    $this->assertEquals('password', $o->getGrantType());
  }

  public function testInfersJwtBearer()
  {
    $o = new OAuth2($this->minimal);
    $o->setIssuer('an issuer');
    $o->setSigningKey('a key');
    $this->assertEquals('urn:ietf:params:oauth:grant-type:jwt-bearer',
                        $o->getGrantType());
  }

  public function testSetsKnownTypes()
  {
    $o = new OAuth2($this->minimal);
    foreach (OAuth2::$knownGrantTypes as $t) {
      $o->setGrantType($t);
      $this->assertEquals($t, $o->getGrantType());
    }
  }

  public function testSetsUrlAsGrantType()
  {
    $o = new OAuth2($this->minimal);
    $o->setGrantType('http://a/grant/url');
    $this->assertInstanceOf('GuzzleHttp\Url', $o->getGrantType());
    $this->assertEquals('http://a/grant/url', strval($o->getGrantType()));
  }
}

class OAuth2TimingTest extends \PHPUnit_Framework_TestCase
{
  private $minimal = [
      'authorizationUri' => 'https://accounts.test.org/insecure/url',
      'redirectUri' => 'https://accounts.test.org/redirect/url',
      'clientId' => 'aClientID'
  ];

  public function testIssuedAtDefaultsToNull()
  {
    $o = new OAuth2($this->minimal);
    $this->assertNull($o->getIssuedAt());
  }

  public function testExpiresAtDefaultsToNull()
  {
    $o = new OAuth2($this->minimal);
    $this->assertNull($o->getExpiresAt());
  }

  public function testExpiresInDefaultsToNull()
  {
    $o = new OAuth2($this->minimal);
    $this->assertNull($o->getExpiresIn());
  }

  public function testSettingExpiresInSetsIssuedAt()
  {
    $o = new OAuth2($this->minimal);
    $this->assertNull($o->getIssuedAt());
    $aShortWhile = 5;
    $o->setExpiresIn($aShortWhile);
    $this->assertEquals($aShortWhile, $o->getExpiresIn());
    $this->assertNotNull($o->getIssuedAt());
  }

  public function testSettingExpiresInSetsExpireAt()
  {
    $o = new OAuth2($this->minimal);
    $this->assertNull($o->getExpiresAt());
    $aShortWhile = 5;
    $o->setExpiresIn($aShortWhile);
    $this->assertNotNull($o->getExpiresAt());
    $this->assertEquals($aShortWhile, $o->getExpiresAt() - $o->getIssuedAt());
  }

  public function testIsNotExpiredByDefault()
  {
    $o = new OAuth2($this->minimal);
    $this->assertFalse($o->isExpired());
  }

  public function testIsNotExpiredIfExpiresAtIsOld()
  {
    $o = new OAuth2($this->minimal);
    $o->setExpiresAt(time() - 2);
    $this->assertTrue($o->isExpired());
  }
}

class OAuth2GeneralTest extends \PHPUnit_Framework_TestCase
{
  private $minimal = [
      'authorizationUri' => 'https://accounts.test.org/insecure/url',
      'redirectUri' => 'https://accounts.test.org/redirect/url',
      'clientId' => 'aClientID'
  ];

  /**
   * @expectedException InvalidArgumentException
   */
  public function testFailsOnUnknownSigningAlgorithm()
  {
    $o = new OAuth2($this->minimal);
    $o->setSigningAlgorithm('this is definitely not an algorithm name');
  }

  public function testAllowsKnownSigningAlgorithms()
  {
    $o = new OAuth2($this->minimal);
    foreach (OAuth2::$knownSigningAlgorithms as $a) {
      $o->setSigningAlgorithm($a);
      $this->assertEquals($a, $o->getSigningAlgorithm());
    }
  }

}
