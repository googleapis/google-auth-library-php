<?php
/*
 * Copyright 2024 Google Inc.
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

namespace Google\Auth\Tests\CredentialSource;

use Google\Auth\CredentialSource\ExecutableSource;
use Google\Auth\ExecutableHandler\ExecutableHandler;
use Google\Auth\ExecutableHandler\ExecutableResponseError;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use RuntimeException;

/**
 * @group credentialsource
 * @group credentialsource-executable
 */
class ExecutableSourceTest extends TestCase
{
    use ProphecyTrait;

    /**
     * @runInSeparateProcess
     */
    public function testNoAllowExecutableEnvVarThrowsException()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            'Pluggable Auth executables need to be explicitly allowed to run by setting the '
            . 'GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES environment Variable to 1.'
        );

        // Ensure env var does not equal 0
        putenv('GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=');
        $source = new ExecutableSource('some-command', null, null);
        $source->fetchSubjectToken();
    }

    /**
     * @dataProvider provideFetchSubjectToken
     * @runInSeparateProcess
     */
    public function testFetchSubjectToken(string $successToken)
    {
        putenv('GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1');

        $cmd = 'fake-command';

        $executableHandler = $this->prophesize(ExecutableHandler::class);
        $executableHandler->__invoke($cmd)
            ->shouldBeCalledOnce()
            ->willReturn(0);
        $executableHandler->getOutput()
            ->shouldBeCalledOnce()
            ->willReturn($successToken);

        $source = new ExecutableSource($cmd, null, $executableHandler->reveal());
        $subjectToken = $source->fetchSubjectToken();
        $this->assertEquals('abc', $subjectToken);
    }

    public function provideFetchSubjectToken()
    {
        return [
            ['{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:id_token", "id_token": "abc"}'],
            ['{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:jwt", "id_token": "abc"}'],
            ['{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:saml2", "saml_response": "abc"}']
        ];
    }

    /**
     * @dataProvider provideFetchSubjectTokenWithError
     * @runInSeparateProcess
     */
    public function testFetchSubjectTokenWithError(
        int $returnCode,
        string $output,
        string $expectedExceptionMessage,
        string $outputFile = null
    ) {
        $this->expectException(ExecutableResponseError::class);
        $this->expectExceptionMessage($expectedExceptionMessage);

        putenv('GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1');

        $cmd = 'fake-command';

        $handler = $this->prophesize(ExecutableHandler::class);
        $handler->__invoke($cmd)
            ->shouldBeCalledOnce()
            ->willReturn($returnCode);
        $handler->getOutput()
            ->shouldBeCalledOnce()
            ->willReturn($output);

        $source = new ExecutableSource($cmd, $outputFile, $handler->reveal());
        $source->fetchSubjectToken();
    }

    public function provideFetchSubjectTokenWithError()
    {
        return [
            [1, '', 'The executable failed to run.'],
            [1, 'error', 'The executable failed to run with the following error: error'],
            [0, '{', 'The executable returned an invalid response: {'],
            [0, '{}', 'Executable response must contain a "version" field'],
            [0, '{"version": 1}', 'Executable response must contain a "success" field'],
            [0, '{"version": 1, "success": false}', 'Executable response must contain a "code" field when unsuccessful'],
            [0, '{"version": 1, "success": false, "code": 1}', 'Executable response must contain a "message" field when unsuccessful'],
            [0, '{"version": 1, "success": false, "code": 1, "message": "error!"}', 'error!'],
            [0, '{"version": 1, "success": true}', 'Executable response must contain a "token_type" field'],
            [0, '{"version": 1, "success": true, "token_type": "wrong"}', 'Executable response "token_type" field must be one of'],
            [
                0,
                '{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:saml2"}',
                'Executable response must contain a "saml_response" field when token_type=urn:ietf:params:oauth:token-type:saml2'
            ],
            [
                0,
                '{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:id_token"}',
                'Executable response must contain a "id_token" field when token_type=urn:ietf:params:oauth:token-type:id_token'
            ],
            [
                0,
                '{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:jwt"}',
                'Executable response must contain a "id_token" field when token_type=urn:ietf:params:oauth:token-type:jwt'
            ],
            [
                0,
                '{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:jwt", "id_token": "abc", "expiration_time": 1}',
                'Executable response is expired.',
            ],
            [
                0,
                '{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:jwt", "id_token": "abc"}',
                'The executable response must contain a "expiration_time" field for successful responses when an output_file has been specified in the configuration.',
                '/some/output/file',
            ],
        ];
    }

    /**
     * @dataProvider provideCachedTokenWithError
     * @runInSeparateProcess
     */
    public function testCachedTokenWithError(
        string $cachedToken,
        string $expectedExceptionMessage
    ) {
        $this->expectException(ExecutableResponseError::class);
        $this->expectExceptionMessage($expectedExceptionMessage);

        putenv('GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1');

        $outputFile = tempnam(sys_get_temp_dir(), 'token');
        file_put_contents($outputFile, $cachedToken);

        $cmd = 'fake-command';
        $handler = $this->prophesize(ExecutableHandler::class);
        $handler->__invoke($cmd)->shouldNotBeCalled();
        $handler->getOutput()->shouldNotBeCalled();

        $source = new ExecutableSource($cmd, $outputFile, $handler->reveal());
        $source->fetchSubjectToken();
    }

    public function provideCachedTokenWithError()
    {
        return [
            ['{', 'Error in output file: Error code INVALID_RESPONSE: The executable returned an invalid response: {'],
            ['{}', 'Error in output file: Error code INVALID_EXECUTABLE_RESPONSE: Executable response must contain a "version" field'],
            ['{"version": 1}', 'Error in output file: Error code INVALID_EXECUTABLE_RESPONSE: Executable response must contain a "success" field'],
            ['{"version": 1, "success": false}', 'Error in output file: Error code INVALID_EXECUTABLE_RESPONSE: Executable response must contain a "code" field when unsuccessful'],
            ['{"version": 1, "success": false, "code": 1}', 'Error in output file: Error code INVALID_EXECUTABLE_RESPONSE: Executable response must contain a "message" field when unsuccessful'],
            ['{"version": 1, "success": true}', 'Error in output file: Error code INVALID_EXECUTABLE_RESPONSE: Executable response must contain a "token_type" field'],
            ['{"version": 1, "success": true, "token_type": "wrong"}', 'Error in output file: Error code INVALID_EXECUTABLE_RESPONSE: Executable response "token_type" field must be one of'],
            [
                '{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:saml2"}',
                'Error in output file: Error code INVALID_EXECUTABLE_RESPONSE: Executable response must contain a "saml_response" field when token_type=urn:ietf:params:oauth:token-type:saml2'
            ],
            [
                '{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:id_token"}',
                'Error in output file: Error code INVALID_EXECUTABLE_RESPONSE: Executable response must contain a "id_token" field when token_type=urn:ietf:params:oauth:token-type:id_token'
            ],
            [
                '{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:jwt"}',
                'Error in output file: Error code INVALID_EXECUTABLE_RESPONSE: Executable response must contain a "id_token" field when token_type=urn:ietf:params:oauth:token-type:jwt'
            ],
            [
                '{"version": 1, "success": true, "token_type": "urn:ietf:params:oauth:token-type:jwt", "id_token": "abc"}',
                'Error in output file: Error code INVALID_EXECUTABLE_RESPONSE: The executable response must contain a "expiration_time" field for successful responses when an output_file has been specified in the configuration.'
            ],
        ];
    }

    /**
     * @runInSeparateProcess
     */
    public function testCachedTokenFile()
    {
        putenv('GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1');

        $outputFile = tempnam(sys_get_temp_dir(), 'token');
        file_put_contents($outputFile, json_encode([
            'version' => 1,
            'success' => true,
            'token_type' => 'urn:ietf:params:oauth:token-type:id_token',
            'id_token' => 'abc',
            'expiration_time' => time() + 100,
        ]));

        $source = new ExecutableSource('fake-command', $outputFile);
        $subjectToken = $source->fetchSubjectToken();
        $this->assertEquals('abc', $subjectToken);
    }

    /**
     * @runInSeparateProcess
     */
    public function testCachedTokenFileExpiredCallsExecutable()
    {
        putenv('GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1');

        $cachedToken = [
            'version' => 1,
            'success' => true,
            'token_type' => 'urn:ietf:params:oauth:token-type:id_token',
            'id_token' => 'abc',
            // token is expired
            'expiration_time' => time() - 100,
        ];
        $successToken = ['expiration_time' => time() + 100] + $cachedToken;
        $outputFile = tempnam(sys_get_temp_dir(), 'token');
        file_put_contents($outputFile, json_encode($cachedToken));

        $executableHandler = $this->prophesize(ExecutableHandler::class);
        $executableHandler->__invoke('fake-command')
            ->shouldBeCalledOnce()
            ->willReturn(0);
        $executableHandler->getOutput()
            ->shouldBeCalledOnce()
            ->willReturn(json_encode($successToken));

        $source = new ExecutableSource('fake-command', $outputFile, $executableHandler->reveal());
        $subjectToken = $source->fetchSubjectToken();
        $this->assertEquals('abc', $subjectToken);
    }

    /**
     * @runInSeparateProcess
     */
    public function testCachedTokenFileWithSuccessFalseCallsExecutable()
    {
        putenv('GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1');

        $cachedToken = [
            'version' => 1,
            // token has success=false
            'success' => false,
            'code' => 0,
            'message' => 'error!'
        ];
        $successToken = [
            'version' => 1,
            'success' => true,
            'token_type' => 'urn:ietf:params:oauth:token-type:id_token',
            'id_token' => 'abc',
            'expiration_time' => time() + 100,
        ];
        $outputFile = tempnam(sys_get_temp_dir(), 'token');
        file_put_contents($outputFile, json_encode($cachedToken));

        $executableHandler = $this->prophesize(ExecutableHandler::class);
        $executableHandler->__invoke('fake-command')
            ->shouldBeCalledOnce()
            ->willReturn(0);
        $executableHandler->getOutput()
            ->shouldBeCalledOnce()
            ->willReturn(json_encode($successToken));

        $source = new ExecutableSource('fake-command', $outputFile, $executableHandler->reveal());
        $subjectToken = $source->fetchSubjectToken();
        $this->assertEquals('abc', $subjectToken);
    }

    /**
     * @runInSeparateProcess
     */
    public function testEmptyCachedTokenFileCallsExecutable()
    {
        putenv('GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1');

        $successToken = [
            'version' => 1,
            'success' => true,
            'token_type' => 'urn:ietf:params:oauth:token-type:id_token',
            'id_token' => 'abc',
            'expiration_time' => time() + 100,
        ];
        $outputFile = tempnam(sys_get_temp_dir(), 'token');
        file_put_contents($outputFile, "\n");

        $executableHandler = $this->prophesize(ExecutableHandler::class);
        $executableHandler->__invoke('fake-command')
            ->shouldBeCalledOnce()
            ->willReturn(0);
        $executableHandler->getOutput()
            ->shouldBeCalledOnce()
            ->willReturn(json_encode($successToken));

        $source = new ExecutableSource('fake-command', $outputFile, $executableHandler->reveal());
        $subjectToken = $source->fetchSubjectToken();
        $this->assertEquals('abc', $subjectToken);
    }
}
