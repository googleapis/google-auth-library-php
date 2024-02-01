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
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use UnexpectedValueException;
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
    public function testFetchSubjectToken(string $expectedCommand)
    {
        putenv('GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1');
        $source = new ExecutableSource($expectedCommand, null, null);
        $subjectToken = $source->fetchSubjectToken(
            null,
            function (string $command, array $envVars, &$returnCode) use ($expectedCommand) {
                $this->assertEquals($expectedCommand, $command);
                $this->assertEquals([], $envVars);
                $returnCode = 0;
                return '{"access_token": "abc"}';
            }
        );
        $this->assertEquals('{"access_token": "abc"}', $subjectToken);
    }

    public function provideFetchSubjectToken()
    {
        return [
            ['fake-command'],
            ['bash fake-command --arg1=foo --arg2=bar'],
        ];
    }

    /**
     * @dataProvider provideFetchSubjectToken
     * @runInSeparateProcess
     */
    public function testFetchSubjectTokenWithError(string $returnCode, string $output, string $expectedException)
    {
        putenv('GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1');
        $source = new ExecutableSource($expectedCommand, null, null);
        $subjectToken = $source->fetchSubjectToken(
            null,
            function (string $command, array $envVars, &$returnCode) use ($expectedCommand) {
                $this->assertEquals($expectedCommand, $command);
                $this->assertEquals([], $envVars);
                $returnCode = 1;
                return '{"access_token": "abc"}';
            }
        );
        $this->assertEquals('{"access_token": "abc"}', $subjectToken);
    }

    public function provideFetchSubjectTokenWithError()
    {
        return [
            ['fake-command'],
            ['bash fake-command --arg1=foo --arg2=bar'],
        ];
    }

    // public function testHeaders()
    // {
    //     $handler = function (RequestInterface $request): ResponseInterface {
    //         $this->assertEquals('GET', $request->getMethod());
    //         $this->assertEquals('test.url', (string) $request->getUri());
    //         $this->assertEquals('abc', (string) $request->getHeaderLine('custom-header-1'));
    //         $this->assertEquals('def', (string) $request->getHeaderLine('custom-header-2'));

    //         $body = $this->prophesize(StreamInterface::class);
    //         $body->__toString()->willReturn('xyz');
    //         $response = $this->prophesize(ResponseInterface::class);
    //         $response->getBody()->willReturn($body);

    //         return $response->reveal();
    //     };

    //     $headers = [
    //         'custom-header-1' => 'abc',
    //         'custom-header-2' => 'def',
    //     ];

    //     $source = new UrlSource('test.url', null, null, $headers);
    //     $subjectToken = $source->fetchSubjectToken($handler);
    //     $this->assertEquals('xyz', $subjectToken);
    // }

    // public function testFormatJsonWithNoSubjectTokenFieldNameThrowsException()
    // {
    //     $this->expectException(InvalidArgumentException::class);
    //     $this->expectExceptionMessage('subject_token_field_name must be set when format is JSON');

    //     new UrlSource('test.url', 'json');
    // }

    // public function testFormatJsonWithInvalidSubjectTokenFieldNameThrowsException()
    // {
    //     $this->expectException(UnexpectedValueException::class);
    //     $this->expectExceptionMessage('subject_token_field_name not found in JSON file');

    //     $handler = function (RequestInterface $request): ResponseInterface {
    //         $this->assertEquals('GET', $request->getMethod());
    //         $this->assertEquals('test.url', (string) $request->getUri());

    //         $body = $this->prophesize(StreamInterface::class);
    //         $body->__toString()->willReturn(json_encode(['good_field_name' => 'abc']));
    //         $response = $this->prophesize(ResponseInterface::class);
    //         $response->getBody()->willReturn($body->reveal());

    //         return $response->reveal();
    //     };

    //     (new UrlSource('test.url', 'json', 'bad_field_name'))
    //         ->fetchSubjectToken($handler);
    // }

    // public function testFormatJsonWithInvalidJsonResponseThrowsException()
    // {
    //     $this->expectException(UnexpectedValueException::class);
    //     $this->expectExceptionMessage('Unable to decode JSON response');

    //     $handler = function (RequestInterface $request): ResponseInterface {
    //         $this->assertEquals('GET', $request->getMethod());
    //         $this->assertEquals('test.url', (string) $request->getUri());

    //         $body = $this->prophesize(StreamInterface::class);
    //         $body->__toString()->willReturn('{not-json}');
    //         $response = $this->prophesize(ResponseInterface::class);
    //         $response->getBody()->willReturn($body->reveal());

    //         return $response->reveal();
    //     };

    //     (new UrlSource('test.url', 'json', 'bad_field_name'))
    //         ->fetchSubjectToken($handler);
    // }
}
