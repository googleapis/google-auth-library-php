<?php
header('Content-Type: application/json');

$scenario = $_GET['scenario'] ?? 'success';

if ($scenario === 'server_error') {
    http_response_code(500);
    echo json_encode(['error' => 'Internal Server Error']);
    exit;
}

if ($scenario === 'invalid_json') {
    echo "{ malformed JSON! ";
    exit;
}

$response = [
    'Token' => 'MOCK_SESSION_TOKEN_789',
    'Expiration' => date('Y-m-d\TH:i:s\Z', strtotime('+1 hour'))
];

if ($scenario === 'success') {
    $response['AccessKeyId'] = 'MOCK_ACCESS_KEY_123';
    $response['SecretAccessKey'] = 'MOCK_SECRET_KEY_456';
} elseif ($scenario === 'missing_fields') {
    // Only return Token and Expiration, simulating a bad response without keys.
}

echo json_encode($response);
