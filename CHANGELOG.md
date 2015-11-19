## 0.5.0 (31/12/2015)

### Changes

* The dependency to Guzzle is removed. We are now using PHP-HTTP to make us independent from any transport library. 
* We are using PSR7 requests and responses
* Introduced HttpFactory to create clients and responses

## 0.4.0 (23/04/2015)

### Changes

* Export callback function to update auth metadata ([@stanley-cheung][])
* Adds an implementation of User Refresh Token auth ([@stanley-cheung][])

[@stanley-cheung]: https://github.com/stanley-cheung
