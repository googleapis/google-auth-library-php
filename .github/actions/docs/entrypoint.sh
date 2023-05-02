#!/bin/sh -l

apt-get update
apt-get install -y git
git fetch origin
git reset --hard HEAD

mkdir .docs
mkdir .cache

php vendor/bin/sami.php update .github/actions/docs/sami.php
