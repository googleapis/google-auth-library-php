<?php

namespace Google\Auth;

use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7\Request;

/**
 * @internal
 */
trait TrustBoundaryTrait
{
    use CacheTrait;

    private bool $enableTrustBoundary = false;

    /**
     * @param array<mixed> $headers
     * @return null|array{locations: array<string>, encodedLocations: string}
     */
    private function getTrustBoundary(
        string $universeDomain,
        callable $httpHandler,
        string $serviceAccountEmail,
        array $headers,
    ): array|null {
        if (!$this->enableTrustBoundary) {
            // Only look up the trust boundary if the credentials have been configured to do so
            return null;
        }

        if ($universeDomain !== GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN) {
            // Universe domain is not default, so trust boundary is not supported.
            return null;
        }

        // Return cached value if it exists
        if ($cached = $this->getCachedValue($this->getCacheKey() . ':trustboundary')) {
            return $cached;
        }

        if (!array_key_exists('authorization', $headers)) {
            // If we don't have an authorization token we can't look up the trust boundary
            return null;
        }

        $trustBoundary = $this->lookupTrustBoundary(
            $httpHandler,
            $serviceAccountEmail,
            $headers['authorization']
        );

        if (null !== $trustBoundary && !array_key_exists('encodedLocations', $trustBoundary)) {
            throw new \LogicException('Trust boundary lookup failed to return \'encodedLocations\'');
        }

        // Save to cache
        $this->setCachedValue($this->getCacheKey() . ':trustboundary', $trustBoundary);

        return $trustBoundary;
    }

    /**
     * @param array<string> $authHeader
     * @return null|array{locations: array<string>, encodedLocations: string}
     */
    private function lookupTrustBoundary(
        callable $httpHandler,
        string $serviceAccountEmail,
        array $authHeader
    ): array|null {
        $url = $this->buildTrustBoundaryLookupUrl($serviceAccountEmail);
        $request = new Request('GET', $url);
        $request = $request->withHeader('authorization', $authHeader);
        try {
            $response = $httpHandler($request);
            return json_decode((string) $response->getBody(), true);
        } catch (ClientException $e) {
            // We swallow all errors here - a failed trust boundary lookup
            // should not disrupt client authentication.
        }
        return null;
    }

    private function buildTrustBoundaryLookupUrl(string $serviceAccountEmail): string
    {
        return sprintf(
            'https://iamcredentials.%s/v1/projects/-/serviceAccounts/%s/allowedLocations',
            $this->getUniverseDomain(),
            $serviceAccountEmail
        );
    }

    /**
     * @param array<mixed> $headers
     * @return array<mixed>
     */
    private function updateTrustBoundaryMetadata(
        array $headers,
        string $serviceAccountEmail,
        string $universeDomain,
        ?callable $httpHandler,
    ): array {
        $httpHandler = $httpHandler
            ?: HttpHandlerFactory::build(HttpClientCache::getHttpClient());

        $trustBoundaryInfo = $this->getTrustBoundary(
            $universeDomain,
            $httpHandler,
            $serviceAccountEmail,
            $headers
        );

        if ($trustBoundaryInfo) {
            $headers['x-allowed-locations'] = $trustBoundaryInfo['encodedLocations'];
        }

        return $headers;
    }
}
