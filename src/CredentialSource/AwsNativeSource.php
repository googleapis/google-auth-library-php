<?php
/*
 * Copyright 2023 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Google\Auth\CredentialSource;

use Google\Auth\FetchAuthTokenInterface;
use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Uri;

/**
 * Authenticates requests using IAM credentials.
 */
class AwsNativeSource implements FetchAuthTokenInterface
{
    private const CRED_VERIFICATION_QUERY = 'Action=GetCallerIdentity&Version=2011-06-15';

    private string $regionUrl;
    private string $regionalCredVerificationUrl;
    private ?string $securityCredentialsUrl;

    public function __construct(
        string $regionUrl,
        string $regionalCredVerificationUrl,
        string $securityCredentialsUrl = null
    ) {
        $this->regionUrl = $regionUrl;
        $this->regionalCredVerificationUrl = $regionalCredVerificationUrl;
        $this->securityCredentialsUrl = $securityCredentialsUrl;
    }

    public function fetchAuthToken(callable $httpHandler = null)
    {
        if (is_null($httpHandler)) {
            $httpHandler = HttpHandlerFactory::build(HttpClientCache::getHttpClient());
        }

        $awsToken = self::fetchAwsTokenFromMetadata($httpHandler);

        $signingVars = $this->securityCredentialsUrl
            ? self::getSigningVarsFromUrl(
                $httpHandler,
                $this->securityCredentialsUrl,
                self::getRoleName($httpHandler, $this->securityCredentialsUrl, $awsToken),
                $awsToken
            )
            : self::getSigningVarsFromEnv();

        if (is_null($signingVars)) {
            throw new \LogicException('Unable to get credentials from ENV, and no security credentials URL provided');
        }

        $region = self::getRegion($httpHandler, $this->regionUrl, $awsToken);

        // From here we use the signing vars to create the signed request to receive a token
        [$accessKeyId, $secretAccessKey, $securityToken] = $signingVars;
        $headers = self::getSignedRequestHeaders($region, $accessKeyId, $secretAccessKey, $securityToken);

        return [
            'access_token' => self::fetchAccessTokenFromCredVerificationUrl(
                $httpHandler,
                str_replace('{region}', $region, $this->regionalCredVerificationUrl),
                $headers,
            )
        ];
    }

    /**
     * @internal
     */
    public static function fetchAwsTokenFromMetadata(callable $httpHandler): string
    {
        $url = 'http://169.254.169.254/latest/api/token';
        $headers = [
            'X-aws-ec2-metadata-token-ttl-seconds' => '21600'
        ];
        $request = new Request(
            'PUT',
            $url,
            $headers
        );

        $response = $httpHandler($request);
        return (string) $response->getBody();
    }

    /**
     * @internal
     *
     * @param array<string, string> $signedHeaders
     */
    public static function fetchAccessTokenFromCredVerificationUrl(
        callable $httpHandler,
        string $regionalCredVerificationUrl,
        array $signedHeaders
    ): string {
        $url = new Uri($regionalCredVerificationUrl);
        $url = $url->withQuery(self::CRED_VERIFICATION_QUERY);

        $request = new Request('POST', $url, $signedHeaders + ['accept' => 'application/json']);
        $response = $httpHandler($request);
        $json = json_decode((string) $response->getBody(), true);

        return $json['access_token'];
    }

    /**
     * @see http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
     *
     * @internal
     *
     * @return array<string, string>
     */
    public static function getSignedRequestHeaders(
        string $region,
        string $accessKeyId,
        string $secretAccessKey,
        ?string $securityToken
    ): array {
        $service = 'sts';
        $host = 'sts.amazonaws.com';

        # Create a date for headers and the credential string in ISO-8601 format
        $amzdate = date('Ymd\THis\Z');
        $datestamp = date('Ymd'); # Date w/o time, used in credential scope

        # Create the canonical headers and signed headers. Header names
        # must be trimmed and lowercase, and sorted in code point order from
        # low to high. Note that there is a trailing \n.
        $canonicalHeaders = sprintf("host:%s\nx-amz-date:%s\n", $host, $amzdate);
        if ($securityToken) {
            $canonicalHeaders .= sprintf("x-amz-security-token:%s\n", $securityToken);
        }

        # Step 5: Create the list of signed headers. This lists the headers
        # in the canonicalHeaders list, delimited with ";" and in alpha order.
        # Note: The request can include any headers; $canonicalHeaders and
        # $signedHeaders lists those that you want to be included in the
        # hash of the request. "Host" and "x-amz-date" are always required.
        $signedHeaders = 'host;x-amz-date';
        if ($securityToken) {
            $signedHeaders .= ';x-amz-security-token';
        }

        # Step 6: Create payload hash (hash of the request body content). For GET
        # requests, the payload is an empty string ("").
        $payloadHash = hash('sha256', '');

        # Step 7: Combine elements to create canonical request
        $canonicalRequest = implode("\n", [
            'POST', // method
            '/',   // canonical URL
            self::CRED_VERIFICATION_QUERY, // query string
            $canonicalHeaders,
            $signedHeaders,
            $payloadHash
        ]);

        # ************* TASK 2: CREATE THE STRING TO SIGN*************
        # Match the algorithm to the hashing algorithm you use, either SHA-1 or
        # SHA-256 (recommended)
        $algorithm = 'AWS4-HMAC-SHA256';
        $scope = implode('/', [$datestamp, $region, $service, 'aws4_request']);
        $stringToSign = implode("\n", [$algorithm, $amzdate, $scope, hash('sha256', $canonicalRequest)]);

        # ************* TASK 3: CALCULATE THE SIGNATURE *************
        # Create the signing key using the function defined above.
        // (done above)
        $signingKey = self::getSignatureKey($secretAccessKey, $datestamp, $region, $service);

        # Sign the string_to_sign using the signing_key
        $signature = bin2hex(self::hmacSign($signingKey, $stringToSign));

        # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        # The signing information can be either in a query string value or in
        # a header named Authorization. This code shows how to use a header.
        # Create authorization header and add to request headers
        $authorizationHeader = sprintf(
            '%s Credential=%s/%s, SignedHeaders=%s, Signature=%s',
            $algorithm,
            $accessKeyId,
            $scope,
            $signedHeaders,
            $signature
        );

        # The request can include any headers, but MUST include "host", "x-amz-date",
        # and (for this scenario) "Authorization". "host" and "x-amz-date" must
        # be included in the canonical_headers and signed_headers, as noted
        # earlier. Order here is not significant.
        $headers = [
            'x-amz-date' => $amzdate,
            'Authorization' => $authorizationHeader,
        ];
        if ($securityToken) {
            $headers['x-amz-security-token'] = $securityToken;
        }

        return $headers;
    }

    /**
     * @internal
     */
    public static function getRegion(callable $httpHandler, string $regionUrl, string $awsToken): string
    {
        // get the region/zone from the region URL
        $regionRequest = new Request('GET', $regionUrl, ['X-aws-ec2-metadata-token' => $awsToken]);
        $regionResponse = $httpHandler($regionRequest);

        // Remove last character. For example, if us-east-2b is returned,
        // the region would be us-east-2.
        return substr((string) $regionResponse->getBody(), 0, -1);
    }

    /**
     * @internal
     */
    public static function getRoleName(callable $httpHandler, string $securityCredentialsUrl, string $awsToken): string
    {
        // Get the AWS role name
        $roleRequest = new Request('GET', $securityCredentialsUrl, ['X-aws-ec2-metadata-token' => $awsToken]);
        $roleResponse = $httpHandler($roleRequest);
        $roleName = (string) $roleResponse->getBody();

        return $roleName;
    }

    /**
     * @internal
     *
     * @return array{string, string, ?string}
     */
    public static function getSigningVarsFromUrl(
        callable $httpHandler,
        string $securityCredentialsUrl,
        string $roleName,
        string $awsToken
    ): array {
        // Get the AWS credentials
        $credsRequest = new Request(
            'GET',
            $securityCredentialsUrl . '/' . $roleName,
            ['X-aws-ec2-metadata-token' => $awsToken]
        );
        $credsResponse = $httpHandler($credsRequest);
        $awsCreds = json_decode((string) $credsResponse->getBody(), true);
        return [
            $awsCreds['AccessKeyId'], // accessKeyId
            $awsCreds['SecretAccessKey'], // secretAccessKey
            $awsCreds['Token'], // token
        ];
    }

    /**
     * @internal
     *
     * @return array{string, string, ?string}
     */
    public static function getSigningVarsFromEnv(): ?array
    {
        $accessKeyId = getenv('AWS_ACCESS_KEY_ID');
        $secretAccessKey = getenv('AWS_SECRET_ACCESS_KEY');
        if ($accessKeyId && $secretAccessKey) {
            return [
                $accessKeyId,
                $secretAccessKey,
                getenv('AWS_SESSION_TOKEN') ?: null, // session token (can be null)
            ];
        }

        return null;
    }

    /**
     * Return HMAC hash in binary string
     */
    private static function hmacSign(string $key, string $msg): string
    {
        return hash_hmac('sha256', self::utf8Encode($msg), $key, true);
    }

    /**
     * @TODO add a fallback when mbstring is not available
     */
    private static function utf8Encode(string $string): string
    {
        return mb_convert_encoding($string, 'UTF-8', 'ISO-8859-1');
    }

    private static function getSignatureKey(
        string $key,
        string $dateStamp,
        string $regionName,
        string $serviceName
    ): string {
        $kDate = self::hmacSign(self::utf8Encode('AWS4' . $key), $dateStamp);
        $kRegion = self::hmacSign($kDate, $regionName);
        $kService = self::hmacSign($kRegion, $serviceName);
        $kSigning = self::hmacSign($kService, 'aws4_request');

        return $kSigning;
    }

    /**
     * Not used
     */
    public function getCacheKey()
    {
        return '';
    }

    /**
     * Not used
     */
    public function getLastReceivedToken()
    {
        return null;
    }
}
