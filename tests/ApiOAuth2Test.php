<?php
/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

require_once "BaseTest.php";
require_once realpath(dirname(__FILE__) . '/../autoload.php');

class ApiOAuth2Test extends BaseTest
{

  public function testSign()
  {
    $cache = new Google_Cache_Null();
    $io = new Google_IO_Stream(0, $cache);
    $config = array(
        'client_id' => 'clientId1',
        'client_secret' => 'clientSecret1',
        'redirect_uri' => 'http://localhost',
        'developer_key' => 'devKey',
        'access_type' => 'offline',
        'approval_prompt' => 'force',
        'request_visible_actions' => 'http://foo');
    $oauth = new Google_Auth_OAuth2($cache, $io, $config);

    $req = new Google_Http_Request('http://localhost');
    $req = $oauth->sign($req);

    $this->assertEquals('http://localhost?key=devKey', $req->getUrl());

    // test accessToken
    $oauth->setAccessToken(
        json_encode(
            array(
              'access_token' => 'ACCESS_TOKEN',
              'created' => time(),
              'expires_in' => '3600'
            )
        )
    );

    $req = $oauth->sign($req);
    $auth = $req->getRequestHeader('authorization');
    $this->assertEquals('Bearer ACCESS_TOKEN', $auth);
  }

  public function testRevokeAccess()
  {
    $accessToken = "ACCESS_TOKEN";
    $refreshToken = "REFRESH_TOKEN";
    $accessToken2 = "ACCESS_TOKEN_2";
    $token = "";

    $cache = $this->getCache();
    $response = $this->getMock("Google_Http_Request", array(), array(''));
    $response->expects($this->any())
            ->method('getResponseHttpCode')
            ->will($this->returnValue(200));
    $io = $this->getMock("Google_IO_Stream", array(), array(0, $cache));
    $io->expects($this->any())
        ->method('makeRequest')
        ->will(
            $this->returnCallback(
                function ($request) use (&$token, $response) {
                  $elements = array();
                  parse_str($request->getPostBody(), $elements);
                  $token = isset($elements['token']) ? $elements['token'] : null;
                  return $response;
                }
            )
        );

    // Test with access token.
    $oauth  = new Google_Auth_OAuth2($cache, $io, array());
    $oauth->setAccessToken(
        json_encode(
            array(
              'access_token' => $accessToken,
              'created' => time(),
              'expires_in' => '3600'
            )
        )
    );
    $this->assertTrue($oauth->revokeToken());
    $this->assertEquals($accessToken, $token);

    // Test with refresh token.
    $oauth  = new Google_Auth_OAuth2($cache, $io, array());
    $oauth->setAccessToken(
        json_encode(
            array(
              'access_token' => $accessToken,
              'refresh_token' => $refreshToken,
              'created' => time(),
              'expires_in' => '3600'
            )
        )
    );
    $this->assertTrue($oauth->revokeToken());
    $this->assertEquals($refreshToken, $token);

    // Test with passed in token.
    $this->assertTrue($oauth->revokeToken($accessToken2));
    $this->assertEquals($accessToken2, $token);
  }

  public function testCreateAuthUrl()
  {
    $cache = new Google_Cache_Null();
    $io = new Google_IO_Stream(0, $cache);
    $config = array(
        'client_id' => 'clientId1',
        'client_secret' => 'clientSecret1',
        'redirect_uri' => 'http://localhost',
        'developer_key' => 'devKey',
        'access_type' => 'offline',
        'approval_prompt' => 'force',
        'request_visible_actions' => array('http://foo'),
        'login_hint' => 'bob@example.org');
    $oauth = new Google_Auth_OAuth2($cache, $io, $config);

    $authUrl = $oauth->createAuthUrl("http://googleapis.com/scope/foo");
    $expected = "https://accounts.google.com/o/oauth2/auth"
        . "?response_type=code"
        . "&redirect_uri=http%3A%2F%2Flocalhost"
        . "&client_id=clientId1"
        . "&scope=http%3A%2F%2Fgoogleapis.com%2Fscope%2Ffoo"
        . "&access_type=offline"
        . "&approval_prompt=force"
        . "&login_hint=bob%40example.org";
    $this->assertEquals($expected, $authUrl);

    // Again with a blank login hint (should remove all traces from authUrl)
    $new_config = array_merge($config, array(
        'login_hint' => '',
        'approval_prompt' => '',
        'hd' => 'example.com',
        'openid.realm' => 'example.com',
        'prompt' => 'select_account',
        'include_granted_scopes' => 'true'));
    $oauth = new Google_Auth_OAuth2($cache, $io, $new_config);
    $authUrl = $oauth->createAuthUrl("http://googleapis.com/scope/foo");
    $expected = "https://accounts.google.com/o/oauth2/auth"
        . "?response_type=code"
        . "&redirect_uri=http%3A%2F%2Flocalhost"
        . "&client_id=clientId1"
        . "&scope=http%3A%2F%2Fgoogleapis.com%2Fscope%2Ffoo"
        . "&access_type=offline"
        . "&hd=example.com"
        . "&openid.realm=example.com"
        . "&prompt=select_account"
        . "&include_granted_scopes=true";
    $this->assertEquals($expected, $authUrl);
  }

  /**
   * Most of the logic for ID token validation is in AuthTest -
   * this is just a general check to ensure we verify a valid
   * id token if one exists.
   */
  public function testValidateIdToken()
  {
    if (!$this->checkToken()) {
      return;
    }

    $client = $this->getClient();
    $token = json_decode($client->getAccessToken());
    $segments = explode(".", $token->id_token);
    $this->assertEquals(3, count($segments));
    // Extract the client ID in this case as it wont be set on the test client.
    $data = json_decode(Google_Utils::urlSafeB64Decode($segments[1]));
    $oauth = new Google_Auth_OAuth2($client);
    $ticket = $oauth->verifyIdToken($token->id_token, $data->aud);
    $this->assertInstanceOf(
        "Google_Auth_LoginTicket",
        $ticket
    );
    $this->assertTrue(strlen($ticket->getUserId()) > 0);

    // TODO(ianbarber): Need to be smart about testing/disabling the
    // caching for this test to make sense. Not sure how to do that
    // at the moment.
    $client = $this->getClient();
    $client->setIo(new Google_IO_Stream($client));
    $data = json_decode(Google_Utils::urlSafeB64Decode($segments[1]));
    $oauth = new Google_Auth_OAuth2($client);
    $this->assertInstanceOf(
        "Google_Auth_LoginTicket",
        $oauth->verifyIdToken($token->id_token, $data->aud)
    );
  }

  /**
   * Test that the ID token is properly refreshed.
   */
  public function testRefreshTokenSetsValues()
  {
    $cache = $this->getCache();
    $response_data = json_encode(
        array(
          'access_token' => "ACCESS_TOKEN",
          'id_token' => "ID_TOKEN",
          'expires_in' => "12345",
        )
    );
    $response = $this->getMock("Google_Http_Request", array(), array(''));
    $response->expects($this->any())
            ->method('getResponseHttpCode')
            ->will($this->returnValue(200));
    $response->expects($this->any())
            ->method('getResponseBody')
            ->will($this->returnValue($response_data));
    $io = $this->getMock("Google_IO_Stream", array(), array(0, $cache));
    $io->expects($this->any())
        ->method('makeRequest')
        ->will(
            $this->returnCallback(
                function ($request) use (&$token, $response) {
                  $elements = $request->getPostBody();
                  PHPUnit_Framework_TestCase::assertEquals(
                      $elements['grant_type'],
                      "refresh_token"
                  );
                  PHPUnit_Framework_TestCase::assertEquals(
                      $elements['refresh_token'],
                      "REFRESH_TOKEN"
                  );
                  return $response;
                }
            )
        );
    $oauth = new Google_Auth_OAuth2($cache, $io, array());
    $oauth->refreshToken("REFRESH_TOKEN");
    $token = json_decode($oauth->getAccessToken(), true);
    $this->assertEquals($token['id_token'], "ID_TOKEN");
  }
}
