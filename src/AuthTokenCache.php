<?php

namespace Google\Auth;

/**
 * @internal
 */
abstract class AuthTokenCache
{
    use CacheTrait;

    /**
     * @var int
     */
    private $eagerRefreshThresholdSeconds = 10;

    /**
     * @param string|null $authUri
     * @return array<mixed>|null
     */
    protected function fetchAuthTokenFromCache($authUri = null)
    {
        // Use the cached value if its available.
        //
        // TODO: correct caching; update the call to setCachedValue to set the expiry
        // to the value returned with the auth token.
        //
        // TODO: correct caching; enable the cache to be cleared.

        // if $authUri is set, use it as the cache key
        $cacheKey = $this->getCacheKeyFromAuthUri($authUri);

        $cached = $this->getCachedValue($cacheKey);

        if (is_array($cached)) {
            if (empty($cached['expires_at'])) {
                // If there is no expiration data, assume token is not expired.
                // (for JwtAccess and ID tokens)
                return $cached;
            }
            if ((time() + $this->eagerRefreshThresholdSeconds) < $cached['expires_at']) {
                // access token is not expired
                return $cached;
            }
        }

        return null;
    }

    /**
     * @param array<mixed> $authToken
     * @param string|null  $authUri
     * @return void
     */
    protected function saveAuthTokenInCache($authToken, $authUri = null)
    {
        if (isset($authToken['access_token']) ||
            isset($authToken['id_token'])) {
            // if $authUri is set, use it as the cache key
            $cacheKey = $this->getCacheKeyFromAuthUri($authUri);

            $this->setCachedValue($cacheKey, $authToken);
        }
    }

    protected function hasCache(): bool
    {
        return $this->cache !== null;
    }

    protected function getCacheKeyFromAuthUri(string $authUri = null): string
    {
        return $authUri
            ? $this->getFullCacheKey($authUri)
            : $this->getCacheKey();
    }

    /**
     * @return string
     */
    abstract protected function getCacheKey();
}
