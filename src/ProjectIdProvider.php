<?php
/*
 * Copyright 2019 Google Inc.
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

namespace Google\Auth;

use DomainException;
use Google\Auth\Credentials\GCECredentials;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Psr7\Request;

/**
 * ProjectIdProvider encapsulates the behavior for determining a google-cloud project id.
 *
 * This class allows you to dynamically determine the application's project id. For example:
 *
 *   $provider = new Google\Auth\ProjectIdProvider();
 *   $projectId = $provider->getProjectId();
 *
 */
class ProjectIdProvider
{
    /**
     * Determines the project id for the current project. If one cannot be determined, a DomainException
     * is thrown. The project is determined from the following locations respectively:
     *
     *   1. A Credentials file supplied via the GOOGLE_APPLICATION_CREDENTIALS env variable
     *   2. The default application credentials
     *   3. The Google Cloud SDK configuration command
     *   4. The App Engine Standard env variable
     *   5. The Google Cloud Compute Engine Meta Data service
     *
     * @param callable|null $httpHandler
     * @return string The current project's id.
     * @throws DomainException
     */
    public static function getProjectId(callable $httpHandler = null)
    {
        // List of sources for determining a project id
        $sources = [
            'self::fromApplicationDefaultCredentials' => [],
            'self::fromSdk' => [],
            'self::fromAppEngineStandard' => [],
            'self::fromComputeEngineMetaData' => [$httpHandler],
        ];

        // Look through all of the sources until we find a project id
        foreach ($sources as $callable => $args) {
            $id = call_user_func_array($callable, $args);
            if ($id !== null) {
                return $id;
            }
        }

        throw new DomainException('Could not determine project id');
    }

    /**
     * Check for a project id in the Key File specified in the GOOGLE_APPLICATION_CREDENTIALS
     * environment variable
     *
     * @return string|null
     */
    private static function fromApplicationDefaultCredentials()
    {
        $credentials = CredentialsLoader::fromEnv() ?: CredentialsLoader::fromWellKnownFile();

        if (!isset($credentials['project_id'])) {
            return null;
        }

        return $credentials['project_id'];
    }

    /**
     * Attempts to retrieve a project id from the gcloud sdk
     *
     * @return string|null
     */
    private static function fromSdk()
    {
        $command = 'gcloud config config-helper --format json';

        // exec the command
        $output = static::execute($command);

        // if we didn't receive output, return null
        if (!$output) {
            return null;
        }

        // the output should be json. decode it and check for errors
        $config = json_decode($output, true);

        if (json_last_error() != JSON_ERROR_NONE) {
            return null;
        }

        // the configuration should contain a project id at the specified path
        if (isset($config['configuration']['properties']['core']['project'])) {
            return $config['configuration']['properties']['core']['project'];
        }
    }

    /**
     * Check for the project id available in App Engine Standard Environments
     *
     * @return string|null
     */
    private static function fromAppEngineStandard()
    {
        $appId = getenv('APPLICATION_ID');

        // if we didn't find it, return null
        if (!$appId) {
            return null;
        }

        // find the project id embedded in the string
        // looks something like p~project-name
        $position = strpos($appId, '~');

        if ($position > 0) {
            $appId = substr($appId, $position + 1);
        }

        return $appId;
    }

    /**
     * @param callable|null $httpHandler
     * @return string|null
     * @throws \Exception
     */
    private static function fromComputeEngineMetaData(callable $httpHandler = null)
    {
        if (!GCECredentials::onGce($httpHandler)) {
            return null;
        }

        // Use the injected client if provided, or else instantiate one
        if (!$httpHandler) {
            $httpHandler = HttpHandlerFactory::build();
        }

        // Make a request to the meta data service to get project id
        // If we can't talk to the service and get a request exception, return null
        try {
            $uri = sprintf('http://%s/computeMetadata/v1/project/project-id', GCECredentials::METADATA_IP);
            $response = $httpHandler(
                new Request('GET', $uri, ['Metadata-Flavor' => 'Google'])
            );

            return (string) $response->getBody();
        } catch (\Exception $e) {
            return null;
        }
    }

    protected static function execute($command)
    {
        return shell_exec($command);
    }
}
