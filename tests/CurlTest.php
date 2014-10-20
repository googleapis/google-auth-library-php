<?php

require_once realpath(dirname(__FILE__) . '/../autoload.php');

class CurlTest extends PHPUnit_Framework_TestCase
{
  // Requires cURL to be compiled in to PHP
  public function testSimpleRequest()
  {
    $request = new Google_Http_Request('http://www.google.com');
    $curl = new Google_IO_Curl(0, new Google_Cache_Null());
    list($response_data,
         $response_headers,
         $response_http_code) = $curl->executeRequest($request);
    $this->assertEquals(200, $response_http_code);
  }
}

?>
