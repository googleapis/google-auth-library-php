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

use Google\Auth\CredentialSource\FileSource;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

/**
 * @group credentialsource
 * @group credentialsource-file
 */
class FileSourceTest extends TestCase
{
    /** @dataProvider provideFetchSubjectToken */
    public function testFetchSubjectToken(
        string $filename,
        string $expectedToken,
        string $format = null,
        string $subjectTokenFieldName = null
    ) {
        $source = new FileSource($filename, $format, $subjectTokenFieldName);
        $subjectToken = $source->fetchSubjectToken();
        $this->assertEquals($expectedToken, $subjectToken);
    }

    public function provideFetchSubjectToken()
    {
        $file1 = tempnam(sys_get_temp_dir(), 'test1');
        file_put_contents($file1, 'abc');


        $file2 = tempnam(sys_get_temp_dir(), 'test2');
        file_put_contents($file2, json_encode(['token' => 'def']));

        return [
            [$file1, 'abc'],
            [$file2, 'def', 'json', 'token']
        ];
    }

    public function testFormatJsonWithNoSubjectTokenFieldNameThrowsException()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('subject_token_field_name must be set when format is JSON');

        new FileSource('file', 'json');
    }

    public function testFormatJsonWithInvalidSubjectTokenFieldNameThrowsException()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('subject_token_field_name not found in JSON file');

        $file1 = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($file1, json_encode(['good_field_name' => 'abc']));

        (new FileSource($file1, 'json', 'bad_field_name'))
            ->fetchSubjectToken();
    }

    public function testFormatJsonWithInvalidJsonFileThrowsException()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Unable to decode JSON file');

        $file1 = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($file1, '{not-json}');

        (new FileSource($file1, 'json', 'bad_field_name'))
            ->fetchSubjectToken();
    }
}
