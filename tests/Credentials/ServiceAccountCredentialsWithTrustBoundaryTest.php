<?php

namespace Google\Auth\Tests\Credentials;

use Google\Auth\Credentials\ServiceAccountCredentials;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

class ServiceAccountCredentialsWithTrustBoundaryTest extends TestCase
{
    private function createTestJson()
    {
        return [
            'private_key' => file_get_contents(__DIR__ . '/../fixtures/private.pem'),
            'client_email' => 'test@example.com',
        ];
    }

    public function testFetchAuthTokenWithTrustBoundary()
    {
        $trustBoundaryResponse = new Response(200, [], '{"token": "my-token", "authority_selector": "my-selector"}');
        $accessTokenResponse = new Response(200, [], '{"access_token": "my-access-token", "expires_in": 3600}');

        $container = [];
        $history = Middleware::history($container);
        $mock = new MockHandler([$trustBoundaryResponse, $accessTokenResponse]);
        $stack = new HandlerStack($mock);
        $stack->push($history);
        $client = new Client(['handler' => $stack]);

        $creds = new ServiceAccountCredentials('scope', $this->createTestJson());
        $creds->fetchAuthToken(function ($request) use ($client) {
            return $client->send($request);
        });

        $this->assertCount(2, $container);

        // First request is for trust boundary
        $trustBoundaryRequest = $container[0]['request'];
        $this->assertStringContainsString('/computeMetadata/v1/instance/service-accounts/test@example.com/?recursive=true', (string) $trustBoundaryRequest->getUri());

        // Second request is for access token
        $accessTokenRequest = $container[1]['request'];
        $body = (string) $accessTokenRequest->getBody();
        parse_str($body, $params);
        $this->assertArrayHasKey('assertion', $params);
        $jwt = $params['assertion'];
        list($header, $payload, $signature) = explode('.', $jwt);
        $payload = json_decode(base64_decode($payload), true);

        $this->assertArrayHasKey('x-goog-iam-authorization-token', $payload);
        $this->assertEquals('my-token', $payload['x-goog-iam-authorization-token']);
        $this->assertArrayHasKey('x-goog-iam-authority-selector', $payload);
        $this->assertEquals('my-selector', $payload['x-goog-iam-authority-selector']);
    }

    public function testFetchAuthTokenWithTrustBoundarySuppressed()
    {
        $accessTokenResponse = new Response(200, [], '{"access_token": "my-access-token", "expires_in": 3600}');

        $container = [];
        $history = Middleware::history($container);
        $mock = new MockHandler([$accessTokenResponse]);
        $stack = new HandlerStack($mock);
        $stack->push($history);
        $client = new Client(['handler' => $stack]);

        $json = $this->createTestJson();
        $json['universe_domain'] = 'my-universe.com';
        $creds = new ServiceAccountCredentials('scope', $json);

        $creds->fetchAuthToken(function ($request) use ($client) {
            return $client->send($request);
        });

        $this->assertCount(1, $container);

        $accessTokenRequest = $container[0]['request'];
        $body = (string) $accessTokenRequest->getBody();
        parse_str($body, $params);
        $this->assertArrayHasKey('assertion', $params);
        $jwt = $params['assertion'];
        list($header, $payload, $signature) = explode('.', $jwt);
        $payload = json_decode(base64_decode($payload), true);

        $this->assertArrayNotHasKey('x-goog-iam-authorization-token', $payload);
        $this->assertArrayNotHasKey('x-goog-iam-authority-selector', $payload);
    }
}
