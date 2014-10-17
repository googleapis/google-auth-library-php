<?php

require_once realpath(dirname(__FILE__) . '/../autoload.php');

class UtilsTest extends PHPUnit_Framework_TestCase
{
  public function testEncodeAndDecode()
  {
    $test_data = "This is a test string!";
    $encoded = Google_Utils::urlSafeB64Encode($test_data);
    $decoded = Google_Utils::urlSafeB64Decode($encoded);
    $this->AssertEquals($test_data, $decoded);
  }
}

?>