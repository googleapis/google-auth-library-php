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

namespace Google\Auth;

use Google\Http\ClientInterface;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Psr7\Request;
use Psr\Http\Client\ClientExceptionInterface;

/**
 * @internal
 *
 * Compute supports calling the metadata server on Compute Engine.
 *
 *   use Google\Auth\Compute;
 *   use Google\Auth\Http\ClientFactory;
 *
 *   $httpClient = ClientFactory::build();
 *
 *   if (Compute::onCompute($httpClient)) {
 *       $projectIdPath = '/computeMetadata/v1/project/project-id';
 *       $projectId = Compute::getFromMetadata($projectIdPath, $httpClient);
 *   }
 */
final class Compute
{
    /**
     * The metadata IP address on appengine instances.
     *
     * The IP is used instead of the domain 'metadata' to avoid slow responses
     * when not on Compute Engine.
     */
    private const METADATA_IP = '169.254.169.254';

    /**
     * The header whose presence indicates GCE presence.
     */
    private const FLAVOR_HEADER = 'Metadata-Flavor';

    /**
     * Determines if this an App Engine Flexible instance, by accessing the
     * GAE_INSTANCE environment variable.
     *
     * @return bool
     */
    public static function onAppEngineFlexible(): bool
    {
        if ($gaeInstance = getenv('GAE_INSTANCE')) {
            return 'aef-' === substr($gaeInstance, 0, 4);
        }

        return false;
    }

    /**
     * Determines if this a GCE instance, by accessing the expected metadata
     * host.
     *
     * @param ClientInterface $httpClient
     *
     * @return bool
     */
    public static function onCompute(ClientInterface $httpClient): bool
    {
        /**
         * Note: the explicit `timeout` and `tries` below is a workaround. The underlying
         * issue is that resolving an unknown host on some networks will take
         * 20-30 seconds; making this timeout short fixes the issue, but
         * could lead to false negatives in the event that we are on GCE, but
         * the metadata resolution was particularly slow. The latter case is
         * "unlikely" since the expected 4-nines time is about 0.5 seconds.
         * This allows us to limit the total ping maximum timeout to 1.5 seconds
         * for developer desktop scenarios.
         */
        $maxComputePingTries = 3;
        $computePingConnectionTimeoutSeconds = 0.5;
        $checkUri = 'http://' . self::METADATA_IP;
        for ($i = 1; $i <= $maxComputePingTries; ++$i) {
            try {
                // Comment from: oauth2client/client.py
                //
                // Note: the explicit `timeout` below is a workaround. The underlying
                // issue is that resolving an unknown host on some networks will take
                // 20-30 seconds; making this timeout short fixes the issue, but
                // could lead to false negatives in the event that we are on GCE, but
                // the metadata resolution was particularly slow. The latter case is
                // "unlikely".
                $resp = $httpClient->send(
                    new Request(
                        'GET',
                        $checkUri,
                        [self::FLAVOR_HEADER => 'Google']
                    ),
                    ['timeout' => $computePingConnectionTimeoutSeconds]
                );

                return 'Google' == $resp->getHeaderLine(self::FLAVOR_HEADER);
            } catch (ClientExceptionInterface $e) {
            } catch (ClientException $e) {
            } catch (ServerException $e) {
            } catch (RequestException $e) {
            } catch (ConnectException $e) {
            }
        }

        return false;
    }

    /**
     * Fetch the value of a GCE metadata server URI.
     *
     * @param string          $uriPath    the metadata URI path with leading slash
     * @param ClientInterface $httpClient
     *
     * @return string
     */
    public static function getFromMetadata(
        string $uriPath,
        ClientInterface $httpClient
    ): string {
        $uri = 'http://' . self::METADATA_IP . $uriPath;

        $resp = $httpClient->send(
            new Request(
                'GET',
                $uri,
                [self::FLAVOR_HEADER => 'Google']
            )
        );

        return (string) $resp->getBody();
    }
}
