<?php
/*
 * Copyright 2023 Google Inc.
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

use Google\Auth\CredentialSource\UrlSource;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use UnexpectedValueException;

/**
 * @group credentialsource
 * @group credentialsource-url
 */
class UrlSourceTest extends TestCase
{
    use ProphecyTrait;

    /** @dataProvider provideFetchSubjectToken */
    public function testFetchSubjectToken(
        string $responseBody,
        string $expectedToken,
        string $format = null,
        string $subjectTokenFieldName = null
    ) {
        $handler = function (RequestInterface $request) use ($responseBody): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals('test.url', (string) $request->getUri());

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn($responseBody);
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        $source = new UrlSource('test.url', $format, $subjectTokenFieldName);
        $subjectToken = $source->fetchSubjectToken($handler);
        $this->assertEquals($expectedToken, $subjectToken);
    }

    public function provideFetchSubjectToken()
    {
        return [
            ['abc', 'abc', null],
            [json_encode(['token' => 'def']), 'def', 'json', 'token']
        ];
    }

    public function testHeaders()
    {
        $handler = function (RequestInterface $request): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals('test.url', (string) $request->getUri());
            $this->assertEquals('abc', (string) $request->getHeaderLine('custom-header-1'));
            $this->assertEquals('def', (string) $request->getHeaderLine('custom-header-2'));

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn('xyz');
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body);

            return $response->reveal();
        };

        $headers = [
            'custom-header-1' => 'abc',
            'custom-header-2' => 'def',
        ];

        $source = new UrlSource('test.url', null, null, $headers);
        $subjectToken = $source->fetchSubjectToken($handler);
        $this->assertEquals('xyz', $subjectToken);
    }

    public function testFormatJsonWithNoSubjectTokenFieldNameThrowsException()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('subject_token_field_name must be set when format is JSON');

        new UrlSource('test.url', 'json');
    }

    public function testFormatJsonWithInvalidSubjectTokenFieldNameThrowsException()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('subject_token_field_name not found in JSON file');

        $handler = function (RequestInterface $request): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals('test.url', (string) $request->getUri());

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn(json_encode(['good_field_name' => 'abc']));
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        (new UrlSource('test.url', 'json', 'bad_field_name'))
            ->fetchSubjectToken($handler);
    }

    public function testFormatJsonWithInvalidJsonResponseThrowsException()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Unable to decode JSON response');

        $handler = function (RequestInterface $request): ResponseInterface {
            $this->assertEquals('GET', $request->getMethod());
            $this->assertEquals('test.url', (string) $request->getUri());

            $body = $this->prophesize(StreamInterface::class);
            $body->__toString()->willReturn('{not-json}');
            $response = $this->prophesize(ResponseInterface::class);
            $response->getBody()->willReturn($body->reveal());

            return $response->reveal();
        };

        (new UrlSource('test.url', 'json', 'bad_field_name'))
            ->fetchSubjectToken($handler);
    }
}
