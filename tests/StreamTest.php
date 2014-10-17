<?php

require_once realpath(dirname(__FILE__) . '/../autoload.php');

class StreamTest extends PHPUnit_Framework_TestCase
{
  public function testSimpleRequest()
  {
    $request = new Google_Http_Request('http://google.com');
    $stream = new Google_IO_Stream(0, new Google_Cache_Null());
    list($response_data,
         $response_headers,
         $response_http_code) = $stream->executeRequest($request);
    $this->assertEquals(301, $response_http_code);
  }
}

?>