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
use Exception;

/**
 * Authenticates requests using IAM credentials.
 */
class AwsNativeSource implements FetchAuthTokenInterface
{
    private string $regionUrl;
    private string $regionalCredVerificationUrl;
    private ?string $securityCredentialsUrl;

    public function __construct(
        string $regionUrl,
        string $regionalCredVerificationUrl = null,
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

        $region = $this->getRegion($httpHandler);
        $signingVars = $this->securityCredentialsUrl
            ? $this->getSigningVarsFromUrl($httpHandler, $this->securityCredentialsUrl)
            : $this->getSigningVarsFromEnv();

        if (is_null($signingVars)) {
            throw new \LogicException('Unable to get credentials from ENV, and no security credentials URL provided');
        }

        [$accessKeyId, $secretAccessKey, $securityToken] = $signingVars;

        $method = 'GET';
        $service = 'sts';
        $host = 'sts.amazonaws.com';
        $endpoint = 'https://sts.amazonaws.com';
        $request_parameters = 'Action=GetCallerIdentity&Version=2011-06-15';
        // From here we use the signing vars to create the signed request to receive a token
        # Create a date for headers and the credential string
        $amzdate = date('%Y%m%dT%H%M%SZ');
        $datestamp = date('%Y%m%d'); # Date w/o time, used in credential scope

        # ************* TASK 1: CREATE A CANONICAL REQUEST *************
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        # Step 1 is to define the verb (GET, POST, etc.)--already done.

        # Step 2: Create canonical URI--the part of the URI from domain to query
        # string (use '/' if no path)
        $canonical_uri = '/';

        # Step 3: Create the canonical query string. In this example (a GET request),
        # request parameters are in the query string. Query string values must
        # be URL-encoded (space=%20). The parameters must be sorted by name.
        # For this example, the query string is pre-formatted in the request_parameters variable.
        $canonical_querystring = $request_parameters;

        # Step 4: Create the canonical headers and signed headers. Header names
        # must be trimmed and lowercase, and sorted in code point order from
        # low to high. Note that there is a trailing \n.
        $canonical_headers = sprintf("host:%s\nx-amz-date:%s\n", $host, $amzdate);
        if ($securityToken) {
             $canonical_headers .= sprintf("x-amz-security-token:%s\n", $securityToken);
        }

        # Step 5: Create the list of signed headers. This lists the headers
        # in the canonical_headers list, delimited with ";" and in alpha order.
        # Note: The request can include any headers; canonical_headers and
        # signed_headers lists those that you want to be included in the
        # hash of the request. "Host" and "x-amz-date" are always required.
        #signed_headers = 'host;x-amz-date;x-amz-security-token'
        $signed_headers = 'host;x-amz-date';
        if ($securityToken) {
            $signed_headers .= ';x-amz-security-token';
        }

        # Step 6: Create payload hash (hash of the request body content). For GET
        # requests, the payload is an empty string ("").
        $payload_hash = hash('sha256', '');

        # Step 7: Combine elements to create canonical request
        $canonical_request = $method + "\n" . $canonical_uri + "\n" . $canonical_querystring + "\n" . $canonical_headers + "\n" . $signed_headers + "\n" . $payload_hash;

        # ************* TASK 2: CREATE THE STRING TO SIGN*************
        # Match the algorithm to the hashing algorithm you use, either SHA-1 or
        # SHA-256 (recommended)
        $algorithm = 'AWS4-HMAC-SHA256';
        $credential_scope = $datestamp + '/' . $region + '/' . $service + '/' + 'aws4_request';
        $string_to_sign = $algorithm + "\n" +  $amzdate + "\n" +  $credential_scope + "\n" +  hash('sha256', $canonical_request);

        # ************* TASK 3: CALCULATE THE SIGNATURE *************
        # Create the signing key using the function defined above.
        // (done above)
        $signingKey = $this->getSignatureKey($secretAccessKey, $datestamp, $region, $service);

        # Sign the string_to_sign using the signing_key
        $signature = $this->hmacSign($signingKey, $string_to_sign);

        # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        # The signing information can be either in a query string value or in
        # a header named Authorization. This code shows how to use a header.
        # Create authorization header and add to request headers
        $authorization_header = sprintf(
            '%s Credential=%s/%s, SignedHeaders=%s, Signature=%s',
            $algorithm,
            $accessKeyId,
            $credential_scope,
            $signed_headers,
            $signature
        );

        # The request can include any headers, but MUST include "host", "x-amz-date",
        # and (for this scenario) "Authorization". "host" and "x-amz-date" must
        # be included in the canonical_headers and signed_headers, as noted
        # earlier. Order here is not significant.
        # Python note: The 'host' header is added automatically by the Python 'requests' library.
        $headers = [
            'x-amz-date' => $amzdate,
            'Authorization' => $authorization_header,
        ];
        if ($securityToken) {
            $headers['x-amz-security-token'] = $securityToken;
        }
    }

    private function getRegion(callable $httpHandler): string
    {
        // get the region/zone from the region URL
        $regionRequest = new Request($this->regionUrl, 'GET');
        $regionResponse = $httpHandler($regionRequest);

        // Remove last character. For example, if us-east-2b is returned,
        // the region would be us-east-2.
        return substr((string) $regionResponse->getBody(), 0, -1);
    }

    /**
     * @return [string, string, string]
     */
    private function getSigningVarsFromUrl(callable $httpHandler, string $url): array
    {
        // Get the AWS role name
        $roleRequest = new Request($this->securityCredentialsUrl, 'GET');
        $roleResponse = $httpHandler($roleRequest);
        $roleName = (string) $roleResponse->getBody();

        // Get the AWS credentials
        $credsRequest = new Request(
            $this->securityCredentialsUrl . '/' . $roleName,
            'GET'
        );
        $credsResponse = $httpHandler($credsRequest);
        $awsCreds = json_decode((string) $credsResponse->getBody(), true);
        return [
            $awsCreds['AccessKeyId'], // accessKeyId
            $awsCreds['SecretAccessKey'], // secretAccessKey
            $awsCreds['Token'], // token
        ];
    }

    private function getSigningVarsFromEnv(): ?array
    {
        if (isset($_ENV['AWS_ACCESS_KEY_ID'])
            && isset($_ENV['AWS_SECRET_ACCESS_KEY'])
        ) {
            return [
                $_ENV['AWS_ACCESS_KEY_ID'], // accessKeyId
                $_ENV['AWS_SECRET_ACCESS_KEY'], // secretAccessKey
                $_ENV['AWS_SESSION_TOKEN'], // token (can be null)
            ];
        }

        return null;
    }

    private function hmacSign(string $key, string $msg): string
    {
        return hash_hmac('sha256', utf8_encode($msg), $key);
    }

    private function getSignatureKey(
        string $key,
        string $dateStamp,
        string $regionName,
        string $serviceName
    ): string {
        $kDate = $this->hmacSign(utf8_encode('AWS4' . $key), $dateStamp);
        $kRegion = $this->hmacSign($kDate, $regionName);
        $kService = $this->hmacSign($kRegion, $serviceName);
        $kSigning = $this->hmacSign($kService, 'aws4_request');

        return $kSigning;
    }

    public function getCacheKey()
    {
        return '';
    }

    public function getLastReceivedToken()
    {
        return null;
    }
}
