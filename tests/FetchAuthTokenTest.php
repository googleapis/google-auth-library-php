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

use Google\Auth\Credentials\AppIdentityCredentials;
use Google\Auth\Credentials\GCECredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountJwtAccessCredentials;
use Google\Auth\Credentials\UserRefreshCredentials;
use Google\Auth\CredentialsLoader;
use Google\Auth\FetchAuthTokenInterface;
use Google\Auth\OAuth2;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;

class FetchAuthTokenTest extends BaseTest
{
    use ProphecyTrait;

    private $scopes = ['https://www.googleapis.com/auth/drive.readonly'];

    /**
     * @dataProvider provideMakeHttpClient
     */
    public function testMakeHttpClient($fetcherClass)
    {
        $mockFetcher = $this->prophesize($fetcherClass);

        $httpHandlerCalled = false;
        $httpHandler = function () use (&$httpHandlerCalled) {
            $httpHandlerCalled = true;
            return ['access_token' => 'xyz'];
        };

        if (in_array(
            'Google\Auth\GetQuotaProjectInterface',
            class_implements($fetcherClass)
        )) {
            $mockFetcher->getQuotaProject()->shouldBeCalledTimes(1);
        }
        $mockFetcher->fetchAuthToken(Argument::any())
            ->shouldBeCalledTimes(1)
            ->will($httpHandler);
        $mockFetcher->getCacheKey()->willReturn('');

        $tokenCallbackCalled = false;
        $tokenCallback = function ($cacheKey, $accessToken) use (&$tokenCallbackCalled) {
            $tokenCallbackCalled = true;
            $this->assertEquals('xyz', $accessToken);
        };

        if ($this->getGuzzleMajorVersion() === 5) {
            $clientOptions = [
                'base_url' => 'https://www.googleapis.com/books/v1/',
                'defaults' => ['exceptions' => false],
            ];
        } else {
            $clientOptions = [
                'base_uri' => 'https://www.googleapis.com/books/v1/',
                'http_errors' => false,
            ];
        }

        $client = CredentialsLoader::makeHttpClient(
            $mockFetcher->reveal(),
            $clientOptions,
            $httpHandler,
            $tokenCallback
        );

        $response = $client->get(
            'volumes?q=Henry+David+Thoreau&country=US'
        );

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertTrue($httpHandlerCalled);
        $this->assertTrue($tokenCallbackCalled);
    }

    public function provideMakeHttpClient()
    {
        return [
            ['Google\Auth\Credentials\AppIdentityCredentials'],
            ['Google\Auth\Credentials\GCECredentials'],
            ['Google\Auth\Credentials\ServiceAccountCredentials'],
            ['Google\Auth\Credentials\ServiceAccountJwtAccessCredentials'],
            ['Google\Auth\Credentials\UserRefreshCredentials'],
            ['Google\Auth\OAuth2'],
        ];
    }

    public function testAppIdentityCredentialsGetLastReceivedToken()
    {
        $class = new \ReflectionClass(
            'Google\Auth\Credentials\AppIdentityCredentials'
        );
        $property = $class->getProperty('lastReceivedToken');
        $property->setAccessible(true);

        $credentials = new AppIdentityCredentials();
        $property->setValue($credentials, [
            'access_token' => 'xyz',
            'expiration_time' => strtotime('2001'),
        ]);

        $this->assertGetLastReceivedToken($credentials);
    }

    public function testGCECredentialsGetLastReceivedToken()
    {
        $class = new \ReflectionClass(
            'Google\Auth\Credentials\GCECredentials'
        );
        $property = $class->getProperty('lastReceivedToken');
        $property->setAccessible(true);

        $credentials = new GCECredentials();
        $property->setValue($credentials, [
            'access_token' => 'xyz',
            'expires_at' => strtotime('2001'),
        ]);

        $this->assertGetLastReceivedToken($credentials);
    }

    public function testServiceAccountCredentialsGetLastReceivedToken()
    {
        $jsonPath = sprintf(
            '%s/fixtures/.config/%s',
            __DIR__,
            CredentialsLoader::WELL_KNOWN_PATH
        );

        $class = new \ReflectionClass(
            'Google\Auth\Credentials\ServiceAccountCredentials'
        );
        $property = $class->getProperty('auth');
        $property->setAccessible(true);

        $oauth2Mock = $this->getOAuth2Mock();
        $oauth2Mock->getScope()
            ->willReturn($this->scopes);
        $oauth2Mock->getAdditionalClaims()
            ->willReturn([]);

        $credentials = new ServiceAccountCredentials($this->scopes, $jsonPath);
        $property->setValue($credentials, $oauth2Mock->reveal());

        $this->assertGetLastReceivedToken($credentials);
    }

    public function testServiceAccountJwtAccessCredentialsGetLastReceivedToken()
    {
        $jsonPath = sprintf(
            '%s/fixtures/.config/%s',
            __DIR__,
            CredentialsLoader::WELL_KNOWN_PATH
        );

        $class = new \ReflectionClass(
            'Google\Auth\Credentials\ServiceAccountJwtAccessCredentials'
        );
        $property = $class->getProperty('auth');
        $property->setAccessible(true);

        $credentials = new ServiceAccountJwtAccessCredentials($jsonPath);
        $property->setValue($credentials, $this->getOAuth2Mock()->reveal());

        $this->assertGetLastReceivedToken($credentials);
    }

    public function testUserRefreshCredentialsGetLastReceivedToken()
    {
        $jsonPath = sprintf(
            '%s/fixtures2/.config/%s',
            __DIR__,
            CredentialsLoader::WELL_KNOWN_PATH
        );

        $class = new \ReflectionClass(
            'Google\Auth\Credentials\UserRefreshCredentials'
        );
        $property = $class->getProperty('auth');
        $property->setAccessible(true);

        $credentials = new UserRefreshCredentials($this->scopes, $jsonPath);
        $property->setValue($credentials, $this->getOAuth2Mock()->reveal());

        $this->assertGetLastReceivedToken($credentials);
    }

    private function getOAuth2()
    {
        $oauth = new OAuth2([
            'access_token' => 'xyz',
            'expires_at' => strtotime('2001'),
        ]);

        $this->assertGetLastReceivedToken($oauth);
    }

    private function getOAuth2Mock()
    {
        $mock = $this->prophesize('Google\Auth\OAuth2');

        $mock->getLastReceivedToken()
            ->shouldBeCalledTimes(1)
            ->willReturn([
                'access_token' => 'xyz',
                'expires_at' => strtotime('2001'),
            ]);

        return $mock;
    }

    private function assertGetLastReceivedToken(FetchAuthTokenInterface $fetcher)
    {
        $accessToken = $fetcher->getLastReceivedToken();

        $this->assertNotNull($accessToken);
        $this->assertArrayHasKey('access_token', $accessToken);
        $this->assertArrayHasKey('expires_at', $accessToken);

        $this->assertEquals('xyz', $accessToken['access_token']);
        $this->assertEquals(strtotime('2001'), $accessToken['expires_at']);
    }
}
