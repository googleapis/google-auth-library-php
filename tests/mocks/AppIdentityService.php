<?php

namespace google\appengine\api\app_identity;

class AppIdentityService
{
  public static $accessToken = array(
    'access_token' => 'xyz',
    'expiration_time' => '2147483646',
  );

  public static function getAccessToken($scope)
  {
    return self::$accessToken;
  }
}
