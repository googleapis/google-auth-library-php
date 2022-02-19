<?php
/*
 * Copyright 2020 Google LLC
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

declare(strict_types=1);

namespace Google\Auth\Credentials;

use Google\Auth\Http\ClientFactory;
use Google\Cache\MemoryCacheItemPool;
use Google\Http\ClientInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Trait for shared functionality between credentials classes.
 *
 * @internal
 */
trait CredentialsTrait
{
    private $maxCacheKeyLength = 64;

    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var CacheItemPoolInterface
     */
    private $cache;

    /**
     * @var int
     */
    private $cacheLifetime = 1500;

    /**
     * @var string
     */
    private $cachePrefix = '';

    /**
     * Returns request headers containing the authorization token.
     *
     * @param string $authUri The optional uri being authorized
     *
     * @return array
     */
    public function getRequestMetadata(string $authUri = null): array
    {
        $result = $this->fetchAuthToken();
        if (isset($result['access_token'])) {
            return ['Authorization' => 'Bearer ' . $result['access_token']];
        }

        return [];
    }

    /**
     * Implements CredentialsInterface#fetchAuthToken.
     *
     * Fetches the auth tokens and caches it based on the default cache
     * configuration.
     *
     * @throws \Exception
     *
     * @return array The auth token
     *
     * Access tokens have the following keys:
     *   - access_token (string)
     *   - expires_in (int)
     *   - token_type (string)
     * ID tokens have the following keys:
     *   - id_token (string)
     */
    public function fetchAuthToken(): array
    {
        $cacheKey = $this->getCacheKey();
        if ($cachedToken = $this->getCachedToken($cacheKey)) {
            return $cachedToken;
        }

        $token = $this->fetchAuthTokenNoCache();

        $this->setCachedToken($cacheKey, $token);

        return $token;
    }

    /**
     * @param array           $options
     * @param ClientInterface $options.httpClient
     */
    private function setHttpClientFromOptions(array $options): void
    {
        if (empty($options['httpClient'])) {
            $options['httpClient'] = ClientFactory::build();
        }
        if (!$options['httpClient'] instanceof ClientInterface) {
            throw new \RuntimeException(sprintf(
                'Invalid option "httpClient": must be an instance of %s',
                ClientInterface::class
            ));
        }
        $this->httpClient = $options['httpClient'];
    }

    /**
     * @param array                  $options
     * @param CacheItemPoolInterface $options.cache
     * @param int                    $options.cacheLifetime
     * @param strring                $options.cachePrefix
     */
    private function setCacheFromOptions(array $options): void
    {
        if (!empty($options['cache'])) {
            if (!$options['cache'] instanceof CacheItemPoolInterface) {
                throw new \RuntimeException(sprintf(
                    'Invalid option "cache": must be an instance of %s',
                    CacheItemPoolInterface::class
                ));
            }
            $this->cache = $options['cache'];
        } else {
            $this->cache = new MemoryCacheItemPool();
        }
        if (array_key_exists('cacheLifetime', $options)) {
            $this->cacheLifetime = (int) $options['cacheLifetime'];
        }
        if (array_key_exists('cachePrefix', $options)) {
            $this->cachePrefix = (string) $options['cachePrefix'];
        }
    }

    private function getCacheKey(): string
    {
        throw new \LogicException(
            'getCacheKey must be implemented in the Credentials class'
        );
    }

    private function fetchAuthTokenNoCache(): array
    {
        throw new \LogicException(
            'fetchAuthTokenNoCache must be implemented in the Credentials class'
        );
    }

    /**
     * Gets the cached value if it is present in the cache when that is
     * available.
     */
    private function getCachedToken(string $cacheKey): ?array
    {
        if (is_null($this->cache)) {
            throw new \LogicException('Cache has not been initialized');
        }

        $key = $this->getFullCacheKey($cacheKey);

        $cacheItem = $this->cache->getItem($key);
        if ($cacheItem->isHit()) {
            return $cacheItem->get();
        }

        return null;
    }

    /**
     * Saves the value in the cache when that is available.
     */
    private function setCachedToken(string $cacheKey, array $token): bool
    {
        if (is_null($this->cache)) {
            throw new \LogicException('Cache has not been initialized');
        }

        $key = $this->getFullCacheKey($cacheKey);

        $cacheItem = $this->cache->getItem($key);
        $cacheItem->set($token);

        // Set token cache expiry to access token expiry when possible
        if (isset($token['expires_at'])) {
            $expiresTimestamp = (string) $token['expires_at'];
            $expiresAt = \DateTime::createFromFormat('U', $expiresTimestamp);
            $cacheItem->expiresAt($expiresAt);
        } elseif (isset($token['expires_in'])) {
            $cacheItem->expiresAfter($token['expires_in']);
        } else {
            $cacheItem->expiresAfter($this->cacheLifetime);
        }

        return $this->cache->save($cacheItem);
    }

    private function getFullCacheKey(string $key): string
    {
        if (empty($key)) {
            throw new \LogicException('Cache key cannot be empty');
        }

        $key = $this->cachePrefix . $key;

        // ensure we do not have illegal characters
        $key = preg_replace('|[^a-zA-Z0-9_\.!]|', '', $key);

        // Hash keys if they exceed $maxKeyLength (defaults to 64)
        if (strlen($this->cachePrefix . $key) > $this->maxCacheKeyLength) {
            $maxKeyLength = $this->maxCacheKeyLength - strlen($this->cachePrefix);
            $key = substr(hash('sha256', $key), 0, $maxKeyLength);
        }

        return $this->cachePrefix . $key;
    }

    /**
     * Throws an exception when targetAudience is supplied to credentials which
     * do not support it.
     */
    private function throwExceptionForTargetAudience(array $options)
    {
        if (isset($options['targetAudience'])) {
            throw new \InvalidArgumentException(sprintf(
                '"targetAudience" is not a valid option for %s',
                __CLASS__
            ));
        }
    }

    /**
     * Parses the JSON key file and sets the quota project if applicable.
     *
     * @param mixed $jsonKey
     */
    private function parseJsonKey($jsonKey): array
    {
        if (is_string($jsonKey)) {
            if (!file_exists($jsonKey)) {
                throw new \InvalidArgumentException('file does not exist');
            }
            $jsonKeyStream = file_get_contents($jsonKey);
            if (!$jsonKey = json_decode($jsonKeyStream, true)) {
                throw new \LogicException('invalid json for auth config');
            }
        }

        if (!is_array($jsonKey)) {
            throw new \InvalidArgumentException(
                'JSON key must be a string or an array'
            );
        }

        if (array_key_exists('quota_project_id', $jsonKey)) {
            $this->quotaProject = (string) $jsonKey['quota_project_id'];
        }

        return $jsonKey;
    }
}
