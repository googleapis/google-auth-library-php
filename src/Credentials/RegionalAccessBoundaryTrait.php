<?php

namespace Google\Auth\Credentials;

use Google\Auth\CacheTrait;
use Google\Auth\GetUniverseDomainInterface;
use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;

/**
 * Trait for implementing Regional Access Boundaries (RAB) in Credentials.
 * @internal
 */
trait RegionalAccessBoundaryTrait
{
    use CacheTrait;

    private bool $enableRegionalAccessBoundary = false;

    /**
     * @param array<mixed> $headers
     * @return null|array{locations: array<string>, encodedLocations: string}
     */
    private function getRegionalAccessBoundary(
        string $universeDomain,
        callable $httpHandler,
        string $regionalAccessBoundaryUrl,
        array $headers,
    ): array|null {
        if (!$this->enableRegionalAccessBoundary) {
            // Only look up the RAB if the credentials have been configured to do so
            return null;
        }

        if ($universeDomain !== GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN) {
            // Universe domain is not default, so RAB is not supported.
            return null;
        }

        if (array_key_exists('x-allowed-locations', $headers)) {
            // If the headers are already set, do not set them
            return null;
        }

        // Return cached value if it exists
        if ($cached = $this->getCachedValue($this->getCacheKey() . ':rab')) {
            return $cached;
        }
        if (!array_key_exists('authorization', $headers)) {
            // If we don't have an authorization token we can't look up the RAB
            return null;
        }

        if ($this->getCachedValue($this->getCacheKey() . ':rab:cooldown')) {
            // We are in a cooldown period, wait until it's over
            return null;
        }

        $regionalAccessBoundary = $this->lookupRegionalAccessBoundary(
            $httpHandler,
            $regionalAccessBoundaryUrl,
            $headers['authorization']
        );

        if (null === $regionalAccessBoundary) {
            // Do not save null RAB to cache. Instead, fail open and try again on a subsequent request.
            return null;
        }

        // Save to cache
        $tbLifetime = 6 * 60 * 60; // 6-hour cache TTL
        $this->setCachedValue($this->getCacheKey() . ':rab', $regionalAccessBoundary, $tbLifetime);

        return $regionalAccessBoundary;
    }

    /**
     * @param array<mixed> $headers
     * @return array<mixed>
     */
    private function updateRegionalAccessBoundaryMetadata(
        array $headers,
        string $regionalAccessBoundaryUrl,
        string $universeDomain,
        ?callable $httpHandler,
    ): array {
        $httpHandler = $httpHandler
            ?: HttpHandlerFactory::build(HttpClientCache::getHttpClient());

        $regionalAccessBoundaryInfo = $this->getRegionalAccessBoundary(
            $universeDomain,
            $httpHandler,
            $regionalAccessBoundaryUrl,
            $headers
        );

        if ($regionalAccessBoundaryInfo) {
            $headers['x-allowed-locations'] = $regionalAccessBoundaryInfo['encodedLocations'];
        }

        return $headers;
    }

    /**
     * Return the RAB lookup URL.
     */
    private function buildRegionalAccessBoundaryLookupUrl(
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
    private function lookupRegionalAccessBoundary(
        callable $httpHandler,
        string $regionalAccessBoundaryUrl,
        array $authHeader
    ): array|null {
        $request = new Request('GET', $regionalAccessBoundaryUrl);
        $request = $request->withHeader('authorization', $authHeader);
        try {
            $response = $httpHandler($request);
        } catch (RequestException $e) {
            // An HTTP error occurred while requesting the RAB lookup
            // We swallow all errors here as a failed RAB lookup
            // should not disrupt client authentication.
            //@TODO Add debug logging
            $this->initiateCooldown();
            return null;
        }

        $regionalAccessBoundary = json_decode((string) $response->getBody(), true);
        if (null === $regionalAccessBoundary) {
            // An error occurred during the JSON parsing of the request body
            // We swallow all errors here as a failed RAB lookup
            // should not disrupt client authentication.
            //@TODO Add debug logging
            $this->initiateCooldown();
            return null;
        }

        if (!array_key_exists('encodedLocations', $regionalAccessBoundary)) {
            // The JSON response did not contain expected "allowLocations"
            // We swallow all errors here as a failed RAB lookup
            // should not disrupt client authentication.
            //@TODO Add debug logging
            $this->initiateCooldown();
            return null;
        }

        /** @var array{locations: array<string>, encodedLocations: string} $regionalAccessBoundary */
        return $regionalAccessBoundary;
    }

    private function initiateCooldown(): void
    {
        $cooldownKey = $this->getCacheKey() . ':rab:cooldown';
        $attempt = $this->getCachedValue($cooldownKey . ':attempt') ?? 0;

        $cooldownBackoff = 15 * 60; // 15 minutes
        $cooldownMax = 6 * 60 * 60; // 6 hours
        $cooldownPeriod = min(++$attempt * $cooldownBackoff, $cooldownMax);
        $this->setCachedValue(
            $cooldownKey,
            true,
            (int) $cooldownPeriod
        );
        $this->setCachedValue(
            $cooldownKey . ':attempt',
            $attempt,
            (int) $cooldownPeriod * 2
        );
    }
}
