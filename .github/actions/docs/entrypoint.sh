#!/bin/sh -l

composer config repositories.sami vcs https://github.com/jdpedrie/sami.git
composer require sami/sami:dev-master

apt-get update
apt-get install -y git

curl -O http://get.sensiolabs.org/sami.phar

git reset HEAD .docs
git reset HEAD .gitmodules

php vendor/bin/sami.php update .github/actions/docs/sami.php

cd ./.docs

git config user.name "GitHub Actions"
git config user.email "actions@github.com"

git add .
git commit -m "Updating docs"
git push -q https://$GITHUB_ACTOR:$GITHUB_TOKEN@github.com/${GITHUB_REPOSITORY} HEAD:gh-pages
