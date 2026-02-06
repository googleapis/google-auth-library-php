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
     * @return null|array{locations: array<string>, encodedLocations: string}
     */
    private function getTrustBoundary(
        ?callable $httpHandler = null,
        string $serviceAccountEmail = 'default'
    ): array|null {
        if (!$this->enableTrustBoundary) {
            // Only look up the trust boundary if the credentials have been configured to do so
            return null;
        }

        if ($this->getUniverseDomain($httpHandler) !== GetUniverseDomainInterface::DEFAULT_UNIVERSE_DOMAIN) {
            // Universe domain is not default, so trust boundary is not supported.
            return null;
        }

        // Return cached value if it exists
        if ($cached = $this->getCachedValue($this->getCacheKey() . ':trustboundary')) {
            return $cached;
        }

        $httpHandler = $httpHandler
            ?: HttpHandlerFactory::build(HttpClientCache::getHttpClient());

        $trustBoundary = $this->lookupTrustBoundary($httpHandler, $serviceAccountEmail);

        if (null !== $trustBoundary && !array_key_exists('encodedLocations', $trustBoundary)) {
            throw new \LogicException('Trust boundary lookup failed to return \'encodedLocations\'');
        }

        // Save to cache
        $this->setCachedValue($this->getCacheKey() . ':trustboundary', $trustBoundary);

        return $trustBoundary;
    }

    /**
     * @return null|array{locations: array<string>, encodedLocations: string}
     */
    private function lookupTrustBoundary(callable $httpHandler, string $serviceAccountEmail): array|null
    {
        $url = $this->buildTrustBoundaryLookupUrl($serviceAccountEmail);
        $request = new Request('GET', $url);
        try {
            $response = $httpHandler($request);
            return json_decode((string) $response->getBody(), true);
        } catch (ClientException $e) {
            // We swallow 404s here. This is because we reasonably expect 404s
            // to be returned from the metadata server for service accounts
            // that do not exist or do not have the required permissions.
            if ($e->getResponse()->getStatusCode() !== 404) {
                throw $e;
            }
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

    private function updateTrustBoundaryMetadata(
        array $headers,
        string $serviceAccountEmail,
        ?callable $httpHandler = null,
    ): array {
        if ($trustBoundaryInfo = $this->getTrustBoundary($httpHandler, $serviceAccountEmail)) {
            $headers['x-allowed-locations'] = $trustBoundaryInfo['encodedLocations'];
        }
        return $headers;
    }
}
