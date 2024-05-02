## 1.21.0 (04/13/2022)

 * [feat]: add support for Firebase v6.0 (#391)

## [1.39.0](https://github.com/googleapis/google-auth-library-php/compare/v1.38.0...v1.39.0) (2024-05-02)


### Features

* Enable auth observability metrics ([#509](https://github.com/googleapis/google-auth-library-php/issues/509)) ([6495f31](https://github.com/googleapis/google-auth-library-php/commit/6495f31061d2d51a173a968dbe65db8dfc6ac3cc))

## [1.38.0](https://github.com/googleapis/google-auth-library-php/compare/v1.37.1...v1.38.0) (2024-04-24)


### Features

* Add ExecutableSource credentials ([#525](https://github.com/googleapis/google-auth-library-php/issues/525)) ([d98900d](https://github.com/googleapis/google-auth-library-php/commit/d98900d47bb5d6eeeaf64fc2a6a8dbde5797f338))

## [1.37.1](https://github.com/googleapis/google-auth-library-php/compare/v1.37.0...v1.37.1) (2024-03-07)


### Bug Fixes

* Use gmdate to format x-amz-date with UTC irrespective of timezone ([#540](https://github.com/googleapis/google-auth-library-php/issues/540)) ([3031d2c](https://github.com/googleapis/google-auth-library-php/commit/3031d2c616902d514867953ede8688d2914d5b11))

## [1.37.0](https://github.com/googleapis/google-auth-library-php/compare/v1.36.0...v1.37.0) (2024-02-21)


### Features

* Add caching for universe domain ([#533](https://github.com/googleapis/google-auth-library-php/issues/533)) ([69249ab](https://github.com/googleapis/google-auth-library-php/commit/69249ab03d4852e55377962752bdda5253f3d574))

## [1.36.0](https://github.com/googleapis/google-auth-library-php/compare/v1.35.0...v1.36.0) (2024-02-20)


### Features

* Universe domain for Iam ([#531](https://github.com/googleapis/google-auth-library-php/issues/531)) ([b905a56](https://github.com/googleapis/google-auth-library-php/commit/b905a561ac8913420d4b3c0a24734ded48687028))

## [1.35.0](https://github.com/googleapis/google-auth-library-php/compare/v1.34.0...v1.35.0) (2024-02-01)


### Features

* Add `expires_in` and `token_type` to tokens from `ServiceAccountJwtAccessCredentials` ([#513](https://github.com/googleapis/google-auth-library-php/issues/513)) ([ee2436d](https://github.com/googleapis/google-auth-library-php/commit/ee2436da42bcf3b2ee09ec8d9eda086293c3a3d9))
* Workforce credentials ([#485](https://github.com/googleapis/google-auth-library-php/issues/485)) ([c1b240f](https://github.com/googleapis/google-auth-library-php/commit/c1b240f77e5d2b97c481c9d1f23bd57524a22553))


### Bug Fixes

* Disallow vulnerable guzzle versions ([#520](https://github.com/googleapis/google-auth-library-php/issues/520)) ([cb782dd](https://github.com/googleapis/google-auth-library-php/commit/cb782dd46db94e5ae514c8e66cff6faddfeb4ed8))

## [1.34.0](https://github.com/googleapis/google-auth-library-php/compare/v1.33.0...v1.34.0) (2024-01-03)


### Features

* Respect sub for domain-wide delegation in service account creds ([#505](https://github.com/googleapis/google-auth-library-php/issues/505)) ([821d4f3](https://github.com/googleapis/google-auth-library-php/commit/821d4f3e5e496c4dfd5e68e58daaa81484f8af99))
* Support universe domain in service account and metadata credentials ([#482](https://github.com/googleapis/google-auth-library-php/issues/482)) ([e4aa874](https://github.com/googleapis/google-auth-library-php/commit/e4aa874e2e1dd321f811b09a80f58d42986bf418))


### Bug Fixes

* ID Token Caching for GCECredentials ([#510](https://github.com/googleapis/google-auth-library-php/issues/510)) ([3222f9e](https://github.com/googleapis/google-auth-library-php/commit/3222f9e5c8d836e21d062ff861b32d3ac867930a))

## [1.33.0](https://github.com/googleapis/google-auth-library-php/compare/v1.32.1...v1.33.0) (2023-11-29)


### Features

* Add and implement universe domain interface ([#477](https://github.com/googleapis/google-auth-library-php/issues/477)) ([35781ed](https://github.com/googleapis/google-auth-library-php/commit/35781ed573aa9d831d38452eefbac790559dfb97))

### Miscellaneous

* Refactor `AuthTokenMiddleware` ([#492](https://github.com/googleapis/google-auth-library-php/pull/492))

## [1.32.1](https://github.com/googleapis/google-auth-library-php/compare/v1.32.0...v1.32.1) (2023-10-17)


### Bug Fixes

* Allowed_algs not properly set for string value ([#489](https://github.com/googleapis/google-auth-library-php/issues/489)) ([0042b52](https://github.com/googleapis/google-auth-library-php/commit/0042b522ebbcffc6d6623e322d162d963eada3b5))

## [1.32.0](https://github.com/googleapis/google-auth-library-php/compare/v1.31.0...v1.32.0) (2023-10-10)


### Features

* Respect cache control for access token certs ([#479](https://github.com/googleapis/google-auth-library-php/issues/479)) ([6d426b5](https://github.com/googleapis/google-auth-library-php/commit/6d426b5cb9462845d2c2d7d506318c9bee613528))

## [1.31.0](https://github.com/googleapis/google-auth-library-php/compare/v1.30.0...v1.31.0) (2023-10-05)


### Features

* Add AWS credential source ([#474](https://github.com/googleapis/google-auth-library-php/issues/474)) ([e5bc897](https://github.com/googleapis/google-auth-library-php/commit/e5bc8979bf87159d9acab1ca8cb7cd7af008b2a6))

## [1.30.0](https://github.com/googleapis/google-auth-library-php/compare/v1.29.1...v1.30.0) (2023-09-07)


### Features

* Add support for BYOID / STS ([#473](https://github.com/googleapis/google-auth-library-php/issues/473)) ([2938e58](https://github.com/googleapis/google-auth-library-php/commit/2938e58d57ac4ed2c952c930d7ffd6ac69e1abb7))

## [1.29.1](https://github.com/googleapis/google-auth-library-php/compare/v1.29.0...v1.29.1) (2023-08-23)


### Bug Fixes

* Use PKCS8 by default for ID token verify ([#466](https://github.com/googleapis/google-auth-library-php/issues/466)) ([0c3a1be](https://github.com/googleapis/google-auth-library-php/commit/0c3a1be78f189e602641b97c487b4092ca17a140))

## [1.29.0](https://github.com/googleapis/google-auth-library-php/compare/v1.28.0...v1.29.0) (2023-08-22)


### Features

* Check unix residency for gce when ping fails ([#469](https://github.com/googleapis/google-auth-library-php/issues/469)) ([3c672f9](https://github.com/googleapis/google-auth-library-php/commit/3c672f9aff61529f4af836558caa50fa29fb9447))

## [1.28.0](https://github.com/googleapis/google-auth-library-php/compare/v1.27.0...v1.28.0) (2023-05-11)


### Features

* Add pkce support ([#454](https://github.com/googleapis/google-auth-library-php/issues/454)) ([1326c81](https://github.com/googleapis/google-auth-library-php/commit/1326c81c759b8f4694297b3d0686727f56bc9937))
* Implement quota project from env var in google/auth ([#452](https://github.com/googleapis/google-auth-library-php/issues/452)) ([a9e8ae3](https://github.com/googleapis/google-auth-library-php/commit/a9e8ae3939e2069437ac998201755784b3c54d98))

## [1.27.0](https://github.com/googleapis/google-auth-library-php/compare/v1.26.0...v1.27.0) (2023-05-02)


### Features

* **deps:** Add support for psr/http-message 2.0 ([#449](https://github.com/googleapis/google-auth-library-php/issues/449)) ([bc71f90](https://github.com/googleapis/google-auth-library-php/commit/bc71f90ef75681fdcd36cf826c130bfb44435806))

## [1.26.0](https://github.com/googleapis/google-auth-library-php/compare/v1.25.0...v1.26.0) (2023-03-30)


### Features

* Access granted scopes  ([#441](https://github.com/googleapis/google-auth-library-php/issues/441)) ([3e5c9f1](https://github.com/googleapis/google-auth-library-php/commit/3e5c9f163b6e45c88afc437d41ecb106d8a9951f))
* Add support for phpseclib3 ([#425](https://github.com/googleapis/google-auth-library-php/issues/425)) ([623acee](https://github.com/googleapis/google-auth-library-php/commit/623acee9b290f14c7402d2b02a2240c6ae37edb2))

## [1.25.0](https://github.com/googleapis/google-auth-library-php/compare/v1.24.0...v1.25.0) (2023-01-26)


### Features

* Add getFetcher to FetchAuthTokenCache ([#431](https://github.com/googleapis/google-auth-library-php/issues/431)) ([cf7ac54](https://github.com/googleapis/google-auth-library-php/commit/cf7ac54454bbb8ad6d12c652c05f5d7b5eb2d701))

## [1.24.0](https://github.com/googleapis/google-auth-library-php/compare/v1.23.1...v1.24.0) (2022-11-28)


### Features

* Add ImpersonatedServiceAccountCredentials ([#421](https://github.com/googleapis/google-auth-library-php/issues/421)) ([de766e9](https://github.com/googleapis/google-auth-library-php/commit/de766e956645dd114478be918363d06fd928b558))

## [1.23.1](https://github.com/googleapis/google-auth-library-php/compare/v1.23.0...v1.23.1) (2022-10-25)


### Bug Fixes

* Do not call GCECredentials::onGCE if ADC has already checked ([#422](https://github.com/googleapis/google-auth-library-php/issues/422)) ([085cc64](https://github.com/googleapis/google-auth-library-php/commit/085cc64c6ae260f917aebf2bc519b4fb6f3400f0))

## [1.23.0](https://github.com/googleapis/google-auth-library-php/compare/v1.22.0...v1.23.0) (2022-09-26)


### Features

* Double default truncateAt for guzzle error output ([#415](https://github.com/googleapis/google-auth-library-php/issues/415)) ([e2f6a89](https://github.com/googleapis/google-auth-library-php/commit/e2f6a89ea0edb040db917b47153d2efb04ecd9bb))

## 1.20.0 (04/11/2022)

 * [feat]: add support for psr/cache:3 (#364)
 * Dropped Support for PHP 5.6 and 7.0

## 1.19.0 (03/24/2022)

 * Dropped support for: 
   * PHP 5.4 and 5.5
   * Guzzle 5
   * Firebase JWT 2.0, 3.0, and 4.0

## 1.18.0 (08/24/2021)

 *  [feat]: Add support for guzzlehttp/psr7 v2 (#357)

## 1.17.0 (08/17/2021)

 * [fix]: consistently use useSelfSignedJwt method in ServiceAccountJwtAccessCredentials (#351)
 * [feat]: add loading and executing of default client cert source (#353)
 * [feat]: add support for proxy-authorization header (#347)

## 1.16.0 (06/22/2021)

 * [feat]: allow ServiceAccountJwtAccessCredentials to sign scopes (#341)
 * [feat]: allow psr/cache:2.0  (#344)

## 1.15.2 (06/21/2021)

 * [fix]: ensure cached tokens are used for GCECredentials::signBlob (#340)
 * [fix]: adds check for getClientName (#336)

## 1.15.1 (04/21/2021)

 * [fix]: update minimum phpseclib for vulnerability fix (#331)

## 1.15.0 (02/05/2021)

 * [feat]: support for PHP 8.0: updated dependencies and tests (#318, #319)

## 1.14.3 (10/16/2020)

 * [fix]: add expires_at to GCECredentials (#314)

## 1.14.2 (10/14/2020)

* [fix]: Better FetchAuthTokenCache and getLastReceivedToken (#311)

## 1.14.1 (10/05/2020)

* [fix]: variable typo (#310)

## 1.14.0 (10/02/2020)

* [feat]: Add support for default scopes (#306)

## 1.13.0 (9/18/2020)

* [feat]: Add service account identity support to GCECredentials (#304)

## 1.12.0 (8/31/2020)

* [feat]: Add QuotaProject option to getMiddleware (#296)
* [feat]: Add caching for calls to GCECredentials::onGce (#301)
* [feat]: Add updateMetadata function to token cache (#298)
* [fix]: Use quota_project_id instead of quota_project (#299)

## 1.11.1 (7/27/2020)

* [fix]: catch ConnectException in GCE check (#294)
* [docs]: Adds [reference docs](https://googleapis.github.io/google-auth-library-php/main)

## 1.11.0 (7/22/2020)

* [feat]: Check cache expiration (#291)
* [fix]: OAuth2 cache key when audience is set (#291)

## 1.10.0 (7/8/2020)

* [feat]: Add support for Guzzle 7 (#256)
* [fix]: Remove SDK warning (#283)
* [chore]: Switch to github pages deploy action (#284)

## 1.9.0 (5/14/2020)

* [feat] Add quotaProject param for extensible client options support (#277)
* [feat] Add signingKeyId param for jwt signing (#270)
* [docs] Misc documentation improvements (#268, #278, #273)
* [chore] Switch from Travis to Github Actions (#273)

## 1.8.0 (3/26/2020)

* [feat] Add option to throw exception in AccessToken::verify(). (#265)
* [feat] Add support for x-goog-user-project. (#254)
* [feat] Add option to specify issuer in AccessToken::verify(). (#267)
* [feat] Add getProjectId to credentials types where project IDs can be determined. (#230)

## 1.7.1 (02/12/2020)

* [fix] Invalid character in iap cert cache key (#263)
* [fix] Typo in exception for package name (#262)

## 1.7.0 (02/11/2020)

* [feat] Add ID token to auth token methods. (#248)
* [feat] Add support for ES256 in `AccessToken::verify`. (#255)
* [fix] Let namespace match the file structure. (#258)
* [fix] Construct RuntimeException. (#257)
* [tests] Update tests for PHP 7.4 compatibility. (#253)
* [chore] Add a couple more things to `.gitattributes`. (#252)

## 1.6.1 (10/29/2019)

* [fix] Handle DST correctly for cache item expirations. (#246)

## 1.6.0 (10/01/2019)

* [feat] Add utility for verifying and revoking access tokens. (#243)
* [docs] Fix README console terminology. (#242)
* [feat] Support custom scopes with GCECredentials. (#239)
* [fix] Fix phpseclib existence check. (#237)

## 1.5.2 (07/22/2019)

* [fix] Move loadItems call out of `SysVCacheItemPool` constructor. (#229)
* [fix] Add `Metadata-Flavor` header to initial GCE metadata call. (#232)

## 1.5.1 (04/16/2019)

* [fix] Moved `getClientName()` from `Google\Auth\FetchAuthTokenInterface`
  to `Google\Auth\SignBlobInterface`, and removed `getClientName()` from
  `InsecureCredentials` and `UserRefreshCredentials`. (#223)

## 1.5.0 (04/15/2019)

### Changes

 * Add support for signing strings with a Credentials instance. (#221)
 * [Docs] Describe the arrays returned by fetchAuthToken. (#216)
 * [Testing] Fix failing tests (#217)
 * Update GitHub issue templates (#214, #213)

## 1.4.0 (09/17/2018)

### Changes

 * Add support for insecure credentials (#208)

## 1.3.3 (08/27/2018)

### Changes

 * Add retry and increase timeout for GCE credentials (#195)
 * [Docs] Fix spelling (#204)
 * Update token url (#206)

## 1.3.2 (07/23/2018)

### Changes

 * Only emits a warning for gcloud credentials (#202)

## 1.3.1 (07/19/2018)

### Changes

 * Added a warning for 3 legged OAuth credentials (#199)
 * [Code cleanup] Removed useless else after return (#193)

## 1.3.0 (06/04/2018)

### Changes

 * Fixes usage of deprecated env var for GAE Flex (#189)
 * fix - guzzlehttp/psr7 dependency version definition (#190)
 * Added SystemV shared memory based CacheItemPool (#191)

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
