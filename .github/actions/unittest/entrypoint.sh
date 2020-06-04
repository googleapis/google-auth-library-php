#!/bin/sh -l

apt-get update && \
apt-get install -y --no-install-recommends \
    git \
    zip \
    curl \
    unzip \
    wget

curl --silent --show-error https://getcomposer.org/installer | php
php composer.phar self-update

echo "---Installing dependencies ---"
echo "${composerargs}"
php $(dirname $0)/retry.php "php composer.phar update $composerargs"

echo "---Running unit tests ---"
vendor/bin/phpunit
