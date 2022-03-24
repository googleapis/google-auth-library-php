#!/bin/sh

# Script used from php-webdriver/php-webdriver

# All commands below must not fail
set -e

# Be in the root dir
cd "$(dirname "$0")/../"

find tests/ -type f -print0 | xargs -0 sed -i 's/function setUp(): void/function setUp()/g';
find tests/ -type f -print0 | xargs -0 sed -i 's/function tearDown(): void/function tearDown()/g';

# Drop the listener from the config file
sed -i '/<listeners>/,+2d' phpunit.xml.dist;

# Return back to original dir
cd - > /dev/null
