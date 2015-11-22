## 0.5.0 (31/12/2015)

### Changes

* The dependency to Guzzle is removed. We are now using PHP-HTTP to make us independent from any transport library. 
* We are using PSR7 requests and responses
* `OAuth2::setAuthorizationUri`, `OAuth2::setRedirectUri` and `OAuth2::SetTokenCredentialUri` do not support an array as first parameter anymore.  

## 0.4.0 (23/04/2015)

### Changes

* Export callback function to update auth metadata ([@stanley-cheung][])
* Adds an implementation of User Refresh Token auth ([@stanley-cheung][])

[@stanley-cheung]: https://github.com/stanley-cheung
