<?php

namespace Google\Auth\Tests\Credentials;

use Google\Auth\Credentials\ImpersonatedServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

class ImpersonatedServiceAccountCredentialsWithTrustBoundaryTest extends TestCase
{
    private function createTestJson()
    {
        return [
            'type' => 'service_account',
            'private_key' => file_get_contents(__DIR__ . '/../fixtures/private.pem'),
            'client_email' => 'test@example.com',
        ];
    }

    public function testFetchAuthTokenWithTrustBoundary()
    {
        $sourceTokenResponse = new Response(200, [], '{"access_token": "source-token", "expires_in": 3600}');
        $trustBoundaryResponse = new Response(200, [], '{"token": "my-token", "authority_selector": "my-selector"}');
        $impersonationResponse = new Response(200, [], '{"accessToken": "impersonated-token", "expireTime": "2025-01-01T00:00:00Z"}');

        $container = [];
        $history = Middleware::history($container);
        $mock = new MockHandler([$sourceTokenResponse, $trustBoundaryResponse, $impersonationResponse]);
        $stack = new HandlerStack($mock);
        $stack->push($history);
        $client = new Client(['handler' => $stack]);
        $handler = function ($request) use ($client) {
            return $client->send($request);
        };

        $sourceCreds = new ServiceAccountCredentials('scope', $this->createTestJson());

        $impersonatedCreds = new ImpersonatedServiceAccountCredentials(
            ['scope'],
            [
                'service_account_impersonation_url' => 'https://iamcredentials.googleapis.com/v1',
                'source_credentials' => $sourceCreds,
            ],
            enableTrustBoundary: true
        );

        $impersonatedCreds->fetchAuthToken($handler);

        $this->assertCount(3, $container);

        // First request is for source token
        $sourceTokenRequest = $container[0]['request'];
        $this->assertEquals('https://oauth2.googleapis.com/token', (string) $sourceTokenRequest->getUri());

        // Second request is for trust boundary
        $trustBoundaryRequest = $container[1]['request'];
        $this->assertStringContainsString(
            '/computeMetadata/v1/instance/service-accounts/default/?recursive=true',
            (string) $trustBoundaryRequest->getUri()
        );

        // Third request is for impersonation
        $impersonationRequest = $container[2]['request'];
        $this->assertTrue($impersonationRequest->hasHeader('x-goog-iam-authorization-token'));
        $this->assertEquals('my-token', $impersonationRequest->getHeaderLine('x-goog-iam-authorization-token'));
        $this->assertTrue($impersonationRequest->hasHeader('x-goog-iam-authority-selector'));
        $this->assertEquals('my-selector', $impersonationRequest->getHeaderLine('x-goog-iam-authority-selector'));
    }
}
