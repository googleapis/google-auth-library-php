<?php

namespace Google\Auth;

use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;

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
        string $trustBoundaryUrl,
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
            $trustBoundaryUrl,
            $headers['authorization']
        );

        if (null !== $trustBoundary && !array_key_exists('encodedLocations', $trustBoundary)) {
            throw new \LogicException('Trust boundary lookup failed to return \'encodedLocations\'');
        }

        // Save to cache
        $tbLifetime = 6 * 60 * 60; // 6-hour cache TTL
        $this->setCachedValue($this->getCacheKey() . ':trustboundary', $trustBoundary, $tbLifetime);

        return $trustBoundary;
    }

    /**
     * @param array<mixed> $headers
     * @return array<mixed>
     */
    private function updateTrustBoundaryMetadata(
        array $headers,
        string $trustBoundaryUrl,
        string $universeDomain,
        ?callable $httpHandler,
    ): array {
        $httpHandler = $httpHandler
            ?: HttpHandlerFactory::build(HttpClientCache::getHttpClient());

        $trustBoundaryInfo = $this->getTrustBoundary(
            $universeDomain,
            $httpHandler,
            $trustBoundaryUrl,
            $headers
        );

        if ($trustBoundaryInfo) {
            $headers['x-allowed-locations'] = $trustBoundaryInfo['encodedLocations'];
        }

        return $headers;
    }

    /**
     * Return the trust boundary lookup URL.
     */
    private function buildTrustBoundaryLookupUrl(
        ?string $serviceAccountEmail = null,
        ?string $poolId = null,
        ?string $projectNumber = null,
    ): string {
        $baseUrl = 'https://iamcredentials.googleapis.com/v1';
        if ($serviceAccountEmail) {
            if (is_null($projectNumber) && is_null($poolId)) {
                return sprintf(
                    '%s/projects/-/serviceAccounts/%s/allowedLocations',
                    $baseUrl,
                    $serviceAccountEmail
                );
            }
        } elseif ($poolId) {
            if (is_null($projectNumber)) {
                // Workforce Identity Pools
                return sprintf(
                    '%s/locations/global/workforcePools/%s/allowedLocations',
                    $baseUrl,
                    $poolId
                );
            }
            // Workload Identity Pools
            return sprintf(
                '%s/projects/%s/locations/global/workloadIdentityPools/%s/allowedLocations',
                $baseUrl,
                $projectNumber,
                $poolId
            );
        }

        throw new InvalidArgumentException('Must supply $serviceAccountEmail, $poolId, or both $poolId and $projectId');
    }

    /**
     * @param array<string> $authHeader
     * @return null|array{locations: array<string>, encodedLocations: string}
     */
    private function lookupTrustBoundary(
        callable $httpHandler,
        string $trustBoundaryUrl,
        array $authHeader
    ): array|null {
        $request = new Request('GET', $trustBoundaryUrl);
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
}
