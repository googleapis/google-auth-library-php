<?php

namespace Google\Auth\Tests;

use Google\Auth\Credentials\GCECredentials;
use Google\Auth\CredentialsLoader;
use Google\Auth\ProjectIdProvider;
use PHPUnit\Framework\TestCase;

class ProjectIdProviderTest extends TestCase
{
    private $home;
    public function setUp()
    {
        $this->home = getenv('HOME');
    }

    public function tearDown()
    {
        putenv('HOME=' . $this->home);
        parent::tearDown();
    }

    public function invokeReflectionMethod($methodName, $arg = null)
    {
        $method = new \ReflectionMethod('Google\Auth\ProjectIdProvider', $methodName);
        $method->setAccessible(true);

        return $method->invoke(null, $arg);
    }

    public function mockSdkOutput($output)
    {
        $method = new \ReflectionMethod('Google\Auth\Tests\ProjectIdProviderShellMock', 'fromSdk');
        $method->setAccessible(true);

        // In the mock, this command isn't used, but it's here for in code documentation.
        $command = 'gcloud config config-helper --format json';

        // Set the static output for this test
        ProjectIdProviderShellMock::setOutput($output);

        $id = $method->invoke(null, $command);

        // Reset the static output to null
        ProjectIdProviderShellMock::setOutput(null);

        return $id;
    }

    public function testFromKeyFile()
    {
        $keyFile = __DIR__ . '/fixtures/private.json';
        putenv(CredentialsLoader::ENV_VAR . '=' . $keyFile);

        $id = ProjectIdProvider::getProjectId();

        $this->assertEquals($id, 'example-project');

        putenv(CredentialsLoader::ENV_VAR);
    }

    public function testFromApplicationDefaultCredentials()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');

        $id = ProjectIdProvider::getProjectId();
        $this->assertEquals($id, 'example-default-project');
    }

    public function testMissingProjectIdInCredentials()
    {
        // The default credentials from alternative defaults is missing project id
        putenv('HOME=' . __DIR__ . '/fixtures/alternative_defaults');

        $id = $this->invokeReflectionMethod('fromApplicationDefaultCredentials');
        $this->assertNull($id);
    }

    public function testFromSdk()
    {
//         This JSON is an example of what is returned from the SDK command
        $config = [
            'configuration' => [
                'active_configuration' => 'example-configuration',
                'properties' => [
                    'core' => [
                        'project' => 'project-id-from-sdk'
                    ]
                ]
            ]
        ];

        $output = json_encode($config);


        $id = $this->mockSdkOutput($output);
        $this->assertEquals($id, 'project-id-from-sdk');

        // Run again, with a config that is missing the project id
        $config = [
            'configuration' => [
                'active_configuration' => 'example-configuration',
                'properties' => [
                    'core' => [
                    ]
                ]
            ]
        ];

        $output = json_encode($config);
        $this->assertNull($this->mockSdkOutput($output));

        // Run again, with no output
        $this->assertNull($this->mockSdkOutput(null));
    }

    public function testApplicationDefaultCredentials()
    {
        // The default credentials from alternative defaults is missing project id
        putenv('HOME=' . __DIR__ . '/fixtures/alternative_defaults');

        $id = $this->invokeReflectionMethod('fromApplicationDefaultCredentials');
        $this->assertNull($id);
    }

    public function testAppEngineStandard()
    {
        putenv('APPLICATION_ID=p~example-project-name');
        $id = $this->invokeReflectionMethod('fromAppEngineStandard');
        $this->assertEquals($id, 'example-project-name');

        // Test when an application id is missing
        putenv('APPLICATION_ID');
        $id = $this->invokeReflectionMethod('fromAppEngineStandard');
        $this->assertNull($id);
    }

    public function testComputeEngineMetaData()
    {
        // There are three cases
        // 1. A valid product name is returned from the service
        // 2. The service returns a 500 status code which should be an error
        // 3. The service returns a 400 status code which should be an error
        $handler = getHandler([
            buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], 'project-name-from-ce-meta'),
            buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(500, [], 'Something went wrong'),
            buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(400, [], 'Something went wrong'),
        ]);

        $method = 'fromComputeEngineMetaData';
        $this->assertEquals($this->invokeReflectionMethod($method, $handler), 'project-name-from-ce-meta');
        $this->assertNull($this->invokeReflectionMethod($method, $handler));
        $this->assertNull($this->invokeReflectionMethod($method, $handler));
    }

    /**
     * @expectedException \DomainException
     */
    public function testProviderThrowsErrorWhenNoIdFound()
    {
        // Use a mock request to ensure that the meta data service isn't called
        $handler = getHandler([
            buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(400)
        ]);

        // Use the dev credentials to ensure the default app credentials aren't loaded
        putenv('HOME=' . __DIR__ . '/fixtures/alternative_defaults');

        ProjectIdProviderShellMock::getProjectId($handler);
    }
}

class ProjectIdProviderShellMock extends ProjectIdProvider
{
    private static $output;

    public static function setOutput($output) {
        self::$output = $output;
    }
    protected static function execute($command)
    {
        return self::$output;
    }
}
