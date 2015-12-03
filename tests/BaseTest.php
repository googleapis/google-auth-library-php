<?php

namespace Google\Auth\Tests;

use GuzzleHttp\ClientInterface;

abstract class BaseTest extends \PHPUnit_Framework_TestCase
{
  public function onlyGuzzle6()
  {
    $version = ClientInterface::VERSION;
    if ('6' !== $version[0]) {
      $this->markTestSkipped('Guzzle 6 only');
    }
  }

  public function onlyGuzzle5()
  {
    $version = ClientInterface::VERSION;
    if ('5' !== $version[0]) {
      $this->markTestSkipped('Guzzle 5 only');
    }
  }
}