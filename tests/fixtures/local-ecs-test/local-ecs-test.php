<?php
require __DIR__ . '/../../../vendor/autoload.php';

use Google\Auth\CredentialSource\AwsNativeSource;
use GuzzleHttp\Client;

echo "Starting thorough ECS mock testing suite...\n\n";

$client = new Client(['http_errors' => true]);
$httpHandler = function ($request) use ($client) {
    return $client->send($request);
};

$testsPassed = 0;
$testsFailed = 0;

function runTestCase($name, $setupEnv, $assertion) {
    global $httpHandler, $testsPassed, $testsFailed;
    
    echo "Running Test: $name... ";
    
    // Clear potentially polluting env vars before setup
    putenv('AWS_CONTAINER_CREDENTIALS_FULL_URI');
    putenv('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI');
    putenv('AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE');
    
    $setupEnv();
    
    try {
        $result = AwsNativeSource::getSigningVarsFromEcs($httpHandler);
        $assertion($result, null);
    } catch (\Exception $e) {
        $assertion(null, $e);
    }
}

// 1. Standard Success
runTestCase('Success - Valid Credentials', function() {
    putenv('AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:8080/?scenario=success');
}, function($result, $exception) use (&$testsPassed, &$testsFailed) {
    if ($result && $result[0] === 'MOCK_ACCESS_KEY_123' && $result[1] === 'MOCK_SECRET_KEY_456') {
        echo "✅ PASS\n"; $testsPassed++;
    } else {
        echo "❌ FAIL (Expected valid credentials array)\n"; $testsFailed++;
    }
});

// 2. Invalid Metadata Response (JSON Error)
runTestCase('Error - Invalid JSON Response', function() {
    putenv('AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:8080/?scenario=invalid_json');
}, function($result, $exception) use (&$testsPassed, &$testsFailed) {
    if ($exception instanceof \UnexpectedValueException && strpos($exception->getMessage(), 'Invalid or missing ECS credentials') !== false) {
        echo "✅ PASS\n"; $testsPassed++;
    } else {
        echo "❌ FAIL (Expected UnexpectedValueException)\n"; $testsFailed++;
    }
});

// 3. Missing Required Fields
runTestCase('Error - Missing Fields in JSON', function() {
    putenv('AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:8080/?scenario=missing_fields');
}, function($result, $exception) use (&$testsPassed, &$testsFailed) {
    if ($exception instanceof \UnexpectedValueException && strpos($exception->getMessage(), 'Invalid or missing ECS credentials') !== false) {
        echo "✅ PASS\n"; $testsPassed++;
    } else {
        echo "❌ FAIL (Expected UnexpectedValueException)\n"; $testsFailed++;
    }
});

// 4. Server Error (500)
runTestCase('Error - HTTP 500 Server Error', function() {
    putenv('AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:8080/?scenario=server_error');
}, function($result, $exception) use (&$testsPassed, &$testsFailed) {
    if ($exception instanceof \GuzzleHttp\Exception\ServerException) {
        echo "✅ PASS\n"; $testsPassed++;
    } else {
        echo "❌ FAIL (Expected Guzzle ServerException)\n"; $testsFailed++;
    }
});

// 5. Unreadable Token File
runTestCase('Error - Unreadable Token File', function() {
    putenv('AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:8080/?scenario=success');
    putenv('AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=/path/to/nowhere/that/does/not/exist.txt');
}, function($result, $exception) use (&$testsPassed, &$testsFailed) {
    if ($exception instanceof \RuntimeException && strpos($exception->getMessage(), 'is not readable') !== false) {
        echo "✅ PASS\n"; $testsPassed++;
    } else {
        echo "❌ FAIL (Expected RuntimeException for unreadable file)\n"; $testsFailed++;
    }
});

// 6. Bailout (No Environment Variables)
runTestCase('Success - Bailout (No URIs Set)', function() {
    // We already clear the env vars in runTestCase.
}, function($result, $exception) use (&$testsPassed, &$testsFailed) {
    if ($result === null && $exception === null) {
        echo "✅ PASS\n"; $testsPassed++;
    } else {
        echo "❌ FAIL (Expected null return)\n"; $testsFailed++;
    }
});

echo "\nTest Suite Complete. Passed: $testsPassed, Failed: $testsFailed\n";
if ($testsFailed > 0) {
    exit(1);
}
