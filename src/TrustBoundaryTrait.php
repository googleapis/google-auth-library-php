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

    private bool $isTrustBoundarySuppressed = false;

    private function suppressTrustBoundary(): void
    {
        $this->isTrustBoundarySuppressed = true;
    }

    private function isTrustBoundarySuppressed()
    {
        return $this->isTrustBoundarySuppressed;
    }

    private function refreshTrustBoundary(
        callable $httpHandler,
        string $serviceAccountEmail = 'default'
    ): array|null {
        if ($this->isTrustBoundarySuppressed()) {
            return null;
        }

        // Return cached value if it exists
        if ($cached = $this->getCachedValue($this->getCacheKey() . ':trustboundary')) {
            return $cached;
        }

        $token = $this->lookupTrustBoundary($httpHandler, $serviceAccountEmail);

        // Save to cache
        $this->setCachedValue($this->getCacheKey() . ':trustboundary', $token);

        return $token;
    }

    private function lookupTrustBoundary(callable $httpHandler, string $serviceAccountEmail): array|null
    {
        $url = $this->buildTrustBoundaryLookupUrl($serviceAccountEmail);
        $request = new Request('GET', $url, ['Metadata-Flavor' => 'Google']);
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
        $metadataHost = getenv('GCE_METADATA_HOST') ?: '169.254.169.254';
        return sprintf(
            'http://%s/computeMetadata/v1/instance/service-accounts/%s/?recursive=true',
            $metadataHost,
            $serviceAccountEmail
        );
    }
}
