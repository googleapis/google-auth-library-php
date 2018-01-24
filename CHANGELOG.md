## 1.2.1 (24/01/2018)

### Changes

 * Fixes array merging bug in Guzzle5HttpHandler (#186)
 * Fixes constructor argument bug in Subscriber & Middleware (#184)

## 1.2.0 (6/12/2017)

### Changes

 * Adds async method to HTTP handlers (#176)
 * Misc bug fixes and improvements (#177, #175, #178)

## 1.1.0 (10/10/2017)

### Changes

 * Supports additional claims in JWT tokens (#171)
 * Adds makeHttpClient for creating authorized Guzzle clients (#162)
 * Misc bug fixes/improvements (#168, #161, #167, #170, #143)

## 1.0.1 (31/07/2017)

### Changes

* Adds support for Firebase 5.0 (#159)

## 1.0.0 (12/06/2017)

### Changes

* Adds hashing and shortening to enforce max key length ([@bshaffer])
* Fix for better PSR-6 compliance - verifies a hit before getting the cache item ([@bshaffer])
* README fixes ([@bshaffer])
* Change authorization header key to lowercase ([@stanley-cheung])

## 0.4.0 (23/04/2015)

### Changes

* Export callback function to update auth metadata ([@stanley-cheung][])
* Adds an implementation of User Refresh Token auth ([@stanley-cheung][])

[@bshaffer]: https://github.com/bshaffer
[@stanley-cheung]: https://github.com/stanley-cheung
