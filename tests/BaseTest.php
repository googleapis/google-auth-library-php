<?php

namespace Google\Auth\Tests;

use PHPUnit\Framework\TestCase;

abstract class BaseTest extends TestCase
{
    /**
     * @see Google\Auth\$this->getValidKeyName
     */
    public function getValidKeyName($key)
    {
        return preg_replace('|[^a-zA-Z0-9_\.! ]|', '', $key);
    }
}
