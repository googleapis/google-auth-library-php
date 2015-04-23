# Google Auth Library for PHP

<dl>
  <dt>Homepage</dt><dd><a href="http://www.github.com/google/google-auth-library-php">http://www.github.com/google/google-auth-library-php</a></dd>
  <dt>Authors</dt>
    <dd><a href="mailto:temiola@google.com">Tim Emiola</a></dd>
    <dd><a href="mailto:stanleycheung@google.com">Stanley Cheung</a></dd>
  <dt>Copyright</dt><dd>Copyright © 2015 Google, Inc.</dd>
  <dt>License</dt><dd>Apache 2.0</dd>
</dl>

## Description

This is Google's officially supported PHP client library for using OAuth 2.0
authorization and authentication with Google APIs.

## Alpha

This library is in Alpha. We will make an effort to support the library, but
we reserve the right to make incompatible changes when necessary.

## Install

```bash
$ composer install
```

## Application Default Credentials

This library provides an implementation of
[application default credentials][application default credentials] for PHP.

The Application Default Credentials provide a simple way to get authorization
credentials for use in calling Google APIs.

They are best suited for cases when the call needs to have the same identity
and authorization level for the application independent of the user. This is
the recommended approach to authorize calls to Cloud APIs, particularly when
you're building an application that uses Google Compute Engine.

## License

This library is licensed under Apache 2.0. Full license text is
available in [COPYING][copying].

## Contributing

See [CONTRIBUTING][contributing].

## Support

Please
[report bugs at the project on Github](https://github.com/google/google-auth-library-php/issues). Don't
hesitate to
[ask questions](http://stackoverflow.com/questions/tagged/google-auth-library-php)
about the client or APIs on [StackOverflow](http://stackoverflow.com).

[google-apis-php-client]: (https://github.com/google/google-api-php-client)
[application default credentials]: (https://developers.google.com/accounts/docs/application-default-credentials)
[contributing]: https://github.com/google/google-auth-library-php/tree/master/CONTRIBUTING.md
[copying]: https://github.com/google/google-auth-library-php/tree/master/COPYING

