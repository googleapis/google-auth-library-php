Google Auth Upgrade Guide
=========================

1.0 to 2.0
----------

In order to take advantage of the new features of PHP, Google Auth dropped
support for PHP 7.0 and below. The minimum supported PHP version is now PHP 7.1.
Type hints and return types for functions and methods have been added wherever
possible.

### PHP Language Features (7.1)

*   [Return types](https://wiki.php.net/rfc/return_types) for all functions
*   [Scalar types](https://www.tutorialspoint.com/php7/php7_scalartype_declarations.htm) for scalar function arguments
*   [Strict typing](https://www.php.net/manual/en/functions.arguments.php#functions.arguments.type-declaration.strict) via `declare(strict_types=1)`
*   private constants

### Improved Caching

*   Implements caching in credentials in `CacheTrait` instead of using the
    `CredentialsCache` wrapper:

```php
$auth = new GoogleClient();
$credentials = $auth->makeCredentials([
    'cache' => new MemoryCachePool,
    'cacheLifetime' => 1500, // Could potentially be "cacheOptions.lifetime"
]);
```
*   Implement [in-memory cache](https://github.com/googleapis/google-auth-library-php/tree/master/src/Cache) by default
*   **TODO**: Fix [SysVCachePool race condition](https://github.com/googleapis/google-auth-library-php/issues/226)
*   Better Cache Keys
    *   Different Auth Token types don't overwrite each other (ID tokens vs Access Token)
    *   Ensures unique cache keys for different credentials / scopes / etc
*   Better Token Expiration
    *   Sets cache expiry based on token expiry when possible
    *   **TODO**:
        *   Verify token is not expired before using it
        *   Fix bug where token expiration is never checked ([b/149049606](http://b/149049606))
        *   Set expiration for ID token / JWT / self-signed
        *   Automatic retry for token expiration API exception


### Improved HTTP handling

*   Provides an abstraction from Guzzle HTTP Client
    *   Using the composer "[replace](https://stackoverflow.com/questions/18882201/how-does-the-replace-property-work-with-composer)" keyword, users can ignore sub-dependencies such as Guzzle in favor of a separate HTTP library
*   Replaces Middleware classes with `CredentialsClient` and `ApiKeyClient` classes
*   Adds `Google\Http\ClientInterface` and `Google\Http\PromiseInterface` for
    vendor abstraction.
*   Adds `Google\Http\Client\GuzzleClient`, `Google\Http\Promise\GuzzlePromise`
    and `Google\Http\Client\Psr18Client` implementations.
*   Uses `Guzzle` implementations by default.
*   **TODO**: Consider wrapping Exceptions

**Example**

```php
// By default, Guzzle is used. A custom guzzle client can be passed in:
$guzzleConfig = [ /* some custom config */ ];
$guzzle = new GuzzleHttp\Client($guzzleConfig);
$httpClient = new Google\Http\Client\GuzzleClient($guzzle);
$auth = new GoogleAuth(['httpClient' => $httpClient]);
```

```php
// To use a different HTTP library or create your own:
$httpClient = new class implements Google\Http\ClientInterface {
    public function send(
        RequestInterface $request,
        array $options = []
    ) : ResponseInterface {
        // Send method
    }

    public function sendAsync(
        RequestInterface $request,
        array $options = []
    ) : PromiseInterface {
        // Send Async method
    }
};
$googleAuth = new GoogleAuth(['httpClient' => $httpClient]);
$googleAuth->verify($someJwt);
```

### Improved JWT handling

*   Provides an abstraction from `firebase/jwt` via `Google\Jwt\ClientInterface`
*   Removed dependencies on `phpseclib/phpseclib`, and `kelvinmo/simplejwt`
    *   Using the composer "[replace](https://stackoverflow.com/questions/18882201/how-does-the-replace-property-work-with-composer)" keyword, users can ignore sub-dependencies such as Firebase JWT in favor of a separate JWT library
*   **TODO**: Consider wrapping Exceptions

**Example**


```php
// by default, "firebase/php-jwt` is used via `Google\Jwt\Client\FirebaseClient`
$googleAuth = new GoogleAuth();
$googleAuth->verify($someJwt);
```

```php
// To use a different library or create your own:
$jwt = new class implements Google\Jwt\ClientInterface {
    public function encode(
        array $payload,
        string $signingKey,
        string $signingAlg,
        ?string $keyId
    ): string {
        // encode method
    }

    public function decode(string $jwt, array $keys, array $allowedAlgs): array
    {
        // decode method
    }

    public function parseKeySet(array $keySey): array
    {
        // parseKeySet method
    }
};
$googleAuth = new GoogleAuth(['jwtClient' => $jwt]);
$googleAuth->verify($someJwt);
```

### New `GoogleAuth` class

`GoogleAuth` replaces `ApplicationDefaultCredentials`, and provides a
centralized, single entrypoint to the auth library. It has the following
methods:

```php
namespace Google\Auth;

use Google\Auth\Credentials\CredentialsInterface;

class GoogleAuth
{
    public function makeCredentials(array $options = []): CredentialsInterface;
    public function onCompute(array $options = []): bool;
    public function verify(string $token, array $options = []): bool;
}
```

The new `GoogleAuth` class does the following:

*   Returns Application Default Credentials for the environment.
*   Uses options array instead of list of arguments in method signature.
*   Consolidates HTTP Handler and Caching options in method signatures in favor
    of class constructor config.
*   Removes static methods and public constants.

**Examples**

```php
// create auth client
$googleAuth = new Google\Auth\GoogleAuth([
    'scope' => 'https://www.googleapis.com/auth/drive.readonly',
]);

// create an authorized client using Application Default Credentials
$credentials = $googleAuth->makeCredentials();
$authHttp = new Google\Auth\Http\CredentialsClient($credentials);
$response = $authHttp->send(new Psr\Http\Message\Request('GET', '/')); // or sendAsync
```

```php
// create auth client
$googleAuth = new Google\Auth\GoogleAuth([
    'scope' => 'https://www.googleapis.com/auth/drive.readonly',
]);

// create an authorized client from an existing Guzzle client
$guzzle = new GuzzleHttp\Client();
$authHttp = new CredentialsClient(
  $credentials,
  new Google\Http\Guzzle6Client($guzzle)
);

// make the request
$response = $authHttp->send(new Psr\Http\Message\Request('GET', '/')); // or sendAsync
```

**Example: Metadata**

```php
// 2.0 implementation
$auth = new GoogleAuth();
if ($auth->onCompute()) {
   // ...
}

// 1.0 implementation:
// GCECredentials::onGce($httpHandler = null);
```

### New `CredentialsInterface` and `CredentialsTrait` to replace `CredentialsLoader`

*   Uses options array instead of list of arguments in method signature
*   Renames `updateMetadata` to `getRequestMetadata`
    *   An array of headers is returned instead of updating an existing array
*   Removes **tokenCallback**
    *   Anything done here should be doable with the HttpHandler
    *   Proper caching makes this unnecessary
*   Removes **getUpdateMetadataFunc**
*   Removes **makeInsecureCredentials**
*   `CredentialsTrait` is marked `@internal`


```php
namespace Google\Auth\Credentials;

use Google\Http\ClientInterface;

/**
 * An interface implemented by objects that can fetch auth tokens.
 */
interface CredentialsInterface
{
    public function fetchAuthToken(): array;
    public function getRequestMetadata(): array;
    public function getProjectId(): ?string;
    public function getQuotaProject(): ?string;
}
```

### Improved ID Token auth

*   The `AccessToken` class has been combined with `OAuth2` and `GoogleAuth`
    *   `verify` and cert fetching functions are in `GoogleAuth`
    *   `revoke` function is in the `OAuth2` class
*   Removed `SimpleJWT ` and `phpseclib` dependencies in favor of `openssl` extension
*   Validates options and throws error if `targetAudience` is supplied to credentials which do not support ID token auth
*   **TODO:** Should we make fetching IAP certs or OIDC certs implicit? Right now, the user has to specify the IAP cert URL. Other languages do this. The only downside is we must inspect the JWT header before verifying to determine the algorithm.

**ID token verify**

```php
$googleAuth = new GoogleAuth();
$googleAuth->verify($idToken);
```

**ID token auth**

```php
use Google\Auth\GoogleAuth;
use Google\Auth\Http\CredentialsClient;
use Psr\Http\Message\Request;

// create auth client
$cloudRunUrl = 'https://cloud-run-url';
$googleAuth = new GoogleAuth();

// create an authorized HTTP client and send a request
// @throws InvalidArgumentException if credentials do not support ID Token auth
$credentials = $googleAuth->makeCredentials(['targetAudience' => $cloudRunUrl]);
$client = new CredentialsClient($credentials);
$response = $client->send(new Psr\Http\Message\Request('GET', $cloudRunUrl));
```

### SignBlob Implementation

*   New `SignBlobInterface`
*   Falls back to calling [Service Account Credentials](https://cloud.google.com/iam/docs/reference/credentials/rest) API if `openssl` isn't installed.
*   `ServiceAccountSignerTrait` has been renamed `PrivateKeySignBlobTrait`
*   `IAM` class has been moved into a trait and renamed `ServiceAccountApiSignBlobTrait`
*   `PrivateKeySignBlobTrait` and `ServiceAccountApiSignBlobTrait` are marked `@internal`

### Improved 3LO Support

*   Ensures refresh token is used when access token is expired
*   Adds `OAuth2Credentials` class for wrapping the OAuth2 service
*   Adds support for `credentialsFile` option on `OAuth2`
*   `OAuth2::isExpired` now returns `true` when token expiration is null
*   **TODO**: Consider adding caching to `OAuth2`
*   **TODO**: Consider adding method `hasValidToken`

```php
$oauth = new OAuth2(
    'credentialsFile' => '/path/to/client-credentials.json',
    'scope' => 'https://www.googleapis.com/auth/drive',
]);
```

**3LO example:**

```php
use Google\Auth\OAuth2;
use Google\Auth\Credentials\OAuthCredentials;
use Google\Auth\Http\CredentialsClient;

// Create the auth client
$oauth = new OAuth2([
    'credentialsFile' => '/path/to/client-credentials.json',
    'scope' => 'https://www.googleapis.com/auth/drive',
]);

$accessTokenFile = '/path/to/access-token.json';
if (isset($_GET['code']))
    // If we have a code back from the OAuth 2.0 flow, exchange that for an access token.
    file_put_contents(
        $accessTokenFile,
        json_encode($oauth->fetchAuthTokenWithCode($_GET['code']))
    );
}

if (file_exists($accessTokenFile)) {
    // $accessToken has a refresh token because "access_type" is set to "offline"
    $accessToken = json_decode(file_get_contents($accessTokenFile));
    $oauth->setToken($accessToken);
} else {
    // Redirect the user back to this page after authorization
    $redirectUri = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
    $authUri = $oauth->buildFullAuthorizationUri(['redirect_uri' => $redirectUri]);
    // Redirect the user to the authorization URI
    header('Location: ' . $authUri);
    return;
}

// Make the call with the access token
$http = new CredentialsClient(new OAuthCredentials($oauth));
$http->send(new Request('GET', 'https://www.googleapis.com/drive/v3/files'));
```

### Breaking Changes

#### Class/Interface Renames

<table>
  <tr>
   <td><code>ApplicationDefaultCredentials</code>
<p>
   => <code>GoogleAuth</code>
   </td>
   <td>The classname "<code>GoogleAuth</code>" more clearly provides an entrypoint to the library.
<p>
Consistent with <a href="https://github.com/googleapis/google-auth-library-nodejs/blob/master/src/auth/googleauth.ts">NodeJS</a>.
   </td>
  </tr>
  <tr>
   <td><code>IAM</code>
<p>
   => <code>SignBlob\ServiceAccountApiSignBlobTrait</code>
   </td>
   <td>More explicit name, "<code>IAM</code>" is too generic.
<p>
A trait is a better fit as it's a utility class.
   </td>
  </tr>
  <tr>
   <td><code>Credentials\InsecureCredentials</code>
<p>
   => <code>Credentials\AnonymousCredentials</code>
   </td>
   <td>"Anonymous" is more consistent with <a href="https://cloud.google.com/docs/authentication">our documentation</a>.
   </td>
  </tr>
  <tr>
   <td><code>Credentials\GCECredentials</code>
<p>
   => <code>Credentials\ComputeCredentials</code>
   </td>
   <td>"Compute" represents a suite of products (App Engine, Compute Engine, Cloud Functions, Cloud Run) which all have a metadata server, and so use these credentials.
<p>
Consistent with <a href="https://github.com/googleapis/google-auth-library-nodejs/blob/master/src/auth/computeclient.ts">NodeJS</a>.
   </td>
  </tr>
  <tr>
   <td><code>HttpHandler\HttpHanderFactory</code>
<p>
   => <code>Http\ClientFactory</code>
   </td>
   <td>"HTTP Client" is <a href="https://www.php-fig.org/psr/psr-18/">more Idiomatic</a>.
   </td>
  </tr>
  <tr>
   <td><code>ServiceAccountSignerTrait</code>
<p>
   => <code>SignBlob\PrivateKeySignBlobTrait</code>
   </td>
   <td>More explicit.
<p>
Organized into subdirectory.
   </td>
  </tr>
  <tr>
   <td><code>FetchAuthTokenInterface</code>
<p>
   => <code>Credentials\CredentialsInterface</code>
   </td>
   <td>More intuitive
   </td>
  </tr>
  <tr>
   <td><code>SignBlobInterface</code>
<p>
   => <code>SignBlob\SignBlobInterface</code>
   </td>
   <td>Organized into subdirectory.
   </td>
  </tr>
</table>

**TODO**: Consider marking some classes as `final`

#### Class/Interface Removals

<table>
  <tr>
   <td><code>AccessToken</code>
   </td>
   <td><strong>refactored</strong>
<p>
into <code>GoogleAuth</code> (constants and <code>verify</code> method) and <code>OAuth2 </code>(<code>revoke</code> method)
   </td>
  </tr>
  <tr>
   <td><code>CacheTrait</code>
   </td>
   <td><strong>refactored</strong>
<p>
into <code>Credentials\CredentialsTrait</code>
   </td>
  </tr>
  <tr>
   <td><code>CredentialsLoader</code>
   </td>
   <td><strong>refactored</strong>
<p>
into <code>GoogleAuth</code> (<code>makeCredentials</code> method) and <code>Credentials\CredentialsTrait</code> (<code>getRequestMetadata</code> method). <code>fromEnv</code> and <code>fromWellKnownFile</code> have been made private.
<p>
See <a href="#method-removals">Method Removals</a>
   </td>
  </tr>
  <tr>
   <td><code>FetchAuthTokenCache</code>
   </td>
   <td><strong>not needed</strong>
<p>
Caching happens in <code>CredentialsTrait</code>
<p>
See <a href="#improved-caching">Improved Caching</a>
   </td>
  </tr>
  <tr>
   <td><code>GetQuotaProjectInterface</code>
   </td>
   <td><strong>refactored</strong>
<p>
into <code>Credentials\CredentialsInterface</code>
   </td>
  </tr>
  <tr>
   <td><code>ProjectIdProviderInterface</code>
   </td>
   <td><strong>refactored</strong>
<p>
into <code>Credentials\CredentialsInterface</code>
   </td>
  </tr>
  <tr>
   <td><code>Credentials\AppIdentityCredentials</code>
   </td>
   <td><strong>obsolete</strong>
<p>
The <strong>php55</strong> runtime is no longer supported
   </td>
  </tr>
  <tr>
   <td><code>Credentials\IAMCredentials</code>
   </td>
   <td><strong>not needed</strong>
<p>
This class was never used.
<p>
   </td>
  </tr>
  <tr>
   <td><code>HttpHandler\Guzzle5HttpHandler</code>
   </td>
   <td><strong>obsolete</strong>
<p>
Guzzle 5 is no longer supported
   </td>
  </tr>
  <tr>
   <td><code>HttpHandler\Guzzle6HttpHandler</code>
   </td>
   <td><strong>refactored</strong>
<p>
into <code>Google\Http\Client\GuzzleClient</code>
<p>
See <a href="https://docs.google.com/document/d/1In1uKSqvrHe5M-KX-sgmuGRC9oWLrqe1wxSbvUESBFc/edit#heading=h.pg45fgmqid9a">PHP HTTP</a>
   </td>
  </tr>
  <tr>
   <td><code>HttpHandler\HttpClientCache</code>
   </td>
   <td><strong>not needed</strong>
<p>
This class is no longer necessary.
<p>
   </td>
  </tr>
  <tr>
   <td><code>Middleware\AuthTokenMiddleware</code>
   </td>
   <td><strong>replaced</strong>
<p>
See <code>Http\CredentialsClient</code>
   </td>
  </tr>
  <tr>
   <td><code>Middleware\ScopedAccessTokenMiddleware</code>
   </td>
   <td><strong>not needed</strong>
<p>
This class does not seem useful, and has replaced by <code>OAuth2Credentials</code>
<p>
   </td>
  </tr>
  <tr>
   <td><code>Middleware\SimpleMiddleware</code>
   </td>
   <td><strong>replaced</strong>
<p>
See <code>Http\ApiKeyClient</code>
   </td>
  </tr>
  <tr>
   <td><code>Subscriber\AuthTokenSubscriber</code>
   </td>
   <td><strong>obsolete</strong>
<p>
Guzzle 5 is no longer supported
   </td>
  </tr>
  <tr>
   <td><code>Subscriber\ScopedAccessTokenSubscriber</code>
   </td>
   <td><strong>obsolete</strong>
<p>
Guzzle 5 is no longer supported
   </td>
  </tr>
  <tr>
   <td><code>Subscriber\SimpleSubscriber</code>
   </td>
   <td><strong>obsolete</strong>
<p>
Guzzle 5 is no longer supported
   </td>
  </tr>
</table>



#### Method Removals and Renames


<table>
  <tr>
   <td><code>ApplicationDefaultCredentials</code>
<p>
<code>:: getCredentials</code>
   </td>
   <td><strong>renamed</strong>
<p>
to <code>GoogleAuth::makeCredentials</code>
   </td>
  </tr>
  <tr>
   <td><code>ApplicationDefaultCredentials</code>
<p>
<code>:: getSubscriber</code>
   </td>
   <td><strong>obsolete</strong>
<p>
Guzzle 5 is no longer supported
   </td>
  </tr>
  <tr>
   <td><code>ApplicationDefaultCredentials</code>
<p>
<code>:: getMiddleware</code>
   </td>
   <td><strong>refactored</strong>
<p>
into <code>GoogleAuth::makeCredentials</code> and <code>CredentialsClient</code>
   </td>
  </tr>
  <tr>
   <td><code>ApplicationDefaultCredentials</code>
<p>
<code>:: getIdTokenMiddleware</code>
   </td>
   <td><strong>refactored</strong>
<p>
into <code>GoogleAuth::makeCredentials</code> and <code>CredentialsClient</code>
   </td>
  </tr>
  <tr>
   <td><code>ApplicationDefaultCredentials</code>
<p>
<code>:: getIdTokenCredentials</code>
   </td>
   <td><strong>refactored</strong>
<p>
into <code>GoogleAuth::makeCredentials</code>
   </td>
  </tr>
  <tr>
   <td><code>CredentialsLoader</code>
<p>
<code>:: makeInsecureCredentials</code>
   </td>
   <td><strong>not needed</strong>
<p>
A wrapper method to just create the class is not very useful.
   </td>
  </tr>
  <tr>
   <td><code>CredentialsLoader</code>
<p>
<code>:: fromEnv</code>
   </td>
   <td><strong>made private</strong>
<p>
This is called internally by <code>GoogleAuth::makeCredentials</code>, and can
be made public again if requested.
   </td>
  </tr>
  <tr>
   <td><code>CredentialsLoader</code>
<p>
<code>:: fromWellKnownFile</code>
   </td>
   <td><strong>made private</strong>
<p>
This is called internally by <code>GoogleAuth::makeCredentials</code>, and can
be made public again if requested.
   </td>
  </tr>
  <tr>
   <td><code>CredentialsLoader</code>
<p>
<code>:: getUpdateMetadataFunc</code>
   </td>
   <td><strong>not needed</strong>
<p>
A function to return the callable of another function is not very useful.
<p>
See <a href="#improved-credentials-interface">Improved Credentials Interface</a>
   </td>
  </tr>
  <tr>
   <td><code>CredentialsLoader</code>
<p>
<code>:: updateMetadata</code>
   </td>
   <td><strong>renamed/refactored</strong>
<p>
into <code>CredentialsTrait::getRequestMetadata</code>
<p>
See <a href="#improved-credentials-interface">Improved Credentials Interface</a>
   </td>
  </tr>
  <tr>
   <td><code>FetchAuthTokenInterface</code>
<p>
<code>:: getLastReceivedToken</code>
   </td>
   <td><strong>not needed</strong>
<p>
Proper caching should make this unnecessary
   </td>
  </tr>
  <tr>
   <td><code>FetchAuthTokenInterface</code>
<p>
<code>:: getCacheKey</code>
   </td>
   <td><strong>not needed</strong>
<p>
Proper caching should make this unnecessary
   </td>
  </tr>
  <tr>
  <td><code>GCECredentials</code>
<p>
<code>:: getTokenUri</code>
<p>
<code>:: getClientNameUri</code>
   </td>
   <td><strong>not needed</strong>
<p>
The URIs used to call the metadata server is implementation detail, and does not need to be public
   </td>
  </tr>
  <tr>
   <td><code>ServiceAccountCredentials</code>
<p>
<code>:: setSub</code>
   </td>
   <td><strong>not needed</strong>
<p>
subject can be passed in to the <code>GoogleAuth</code> class
   </td>
  </tr>
  <tr>
   <td><code>SignBlobInterface</code>
<p>
<code>:: getClientName</code>
<p>
   =>
<p>
<code>:: getClientEmail</code>
   </td>
   <td><strong>renamed</strong>
<p>
More accurate description of the returned value (the JSON field is <code>client_email</code> and the metadata URL is <code>service-accounts/default/email</code>
   </td>
  </tr>
  <tr>
   <td><code>OAuth2</code>
<p>
<code>:: updateToken</code>
<p>
   =>
<p>
<code>:: setAuthToken</code>
   </td>
   <td><strong>renamed</strong>
<p>
Consistent with <code>fetchAuthToken</code>
<p>
More clearly identifies that no network calls are made
   </td>
  </tr>
  <tr>
   <td><code>OAuth2</code>
<p>
<code>:: verifyIdToken</code>
   </td>
   <td><strong>refactored</strong>
<p>
This functionality is now in <code>GoogleAuth::verify</code> and
<code>Google\Jwt\ClientInterface::decode</code>.
   </td>
  </tr>
</table>

#### Dropped Library Support

*   Dropped support for Guzzle 5
*   Dropped support for `firebase\php-jwt` 2.0, 3.0, and 4.0
*   Dropped support for App Engine `php55`

#### Other breaking changes

*   The `$tokenCallback` arguments have been removed. See **Improved Credentials Interface**
*   `CredentialsInterface `implementations no longer extend `CredentialsLoader` (as it's been removed)
*   `OAuth2` no longer implements `CredentialsInterface` (previously `FetchAuthTokenInterface`), and instead is passed to an `OAuth2Credentials` object which does.
*   Removed class constant `ApplicationDefaultCredentials::AUTH_METADATA_KEY`
*   Most class constants have been made private. Interface constants are still public.
*   The argument `$forceOpenssl` has been removed from `signBlob` methods
