#!/bin/sh -l

apt-get update
apt-get install -y git
git reset --hard HEAD
git fetch origin

mkdir .docs
mkdir .cache

php vendor/bin/sami.php update .github/actions/docs/sami.php
