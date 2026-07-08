#!/bin/bash
cd "$(dirname "$0")"

echo "Starting mock PHP server on port 8080..."
php -S 127.0.0.1:8080 local-ecs-mock-server.php > /dev/null 2>&1 &
SERVER_PID=$!

sleep 1
echo "Running test client..."
php local-ecs-test.php

echo "Cleaning up..."
kill $SERVER_PID
echo "Done!"
