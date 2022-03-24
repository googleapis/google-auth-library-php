<?php

namespace Google\Auth\Tests;

use GuzzleHttp\ClientInterface;
use PHPUnit\Framework\TestCase;

abstract class BaseTest extends TestCase
{
    protected function onlyGuzzle6()
    {
        if ($this->getGuzzleMajorVersion() !== 6) {
            $this->markTestSkipped('Guzzle 6 only');
        }
    }

    protected function onlyGuzzle7()
    {
        if ($this->getGuzzleMajorVersion() !== 7) {
            $this->markTestSkipped('Guzzle 7 only');
        }
    }

    protected function getGuzzleMajorVersion()
    {
        if (defined('GuzzleHttp\ClientInterface::MAJOR_VERSION')) {
            return ClientInterface::MAJOR_VERSION;
        }

        if (defined('GuzzleHttp\ClientInterface::VERSION')) {
            return (int) substr(ClientInterface::VERSION, 0, 1);
        }

        $this->fail('Unable to determine the currently used Guzzle Version');
    }

    /**
     * @see Google\Auth\$this->getValidKeyName
     */
    public function getValidKeyName($key)
    {
        return preg_replace('|[^a-zA-Z0-9_\.! ]|', '', $key);
    }

    public static function assertStringContainsString(
        string $needle,
        string $haystack,
        string $message = ''
    ): void {
        if (method_exists(TestCase::class, 'assertStringContainsString')) {
            parent::assertStringContainsString($needle, $haystack, $message);

            return;
        }

        self::assertContains($needle, $haystack, $message);
    }

    public static function assertIsArray(
        $actual,
        string $message = ''
    ): void {
        if (method_exists(TestCase::class, 'assertIsArray')) {
            parent::assertIsArray($actual, $message);

            return;
        }

        self::assertInternalType('array', $actual, $message);
    }

    public static function assertIsString(
        $string,
        string $message = ''
    ): void {
        if (method_exists(TestCase::class, 'assertIsString')) {
            parent::assertIsString($string, $message);

            return;
        }

        self::assertInternalType('string', $string, $message);
    }
}
