<?php
/*
 * Copyright 2018 Google Inc.
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

namespace Google\Auth\Tests\Cache;

require_once __DIR__ . '/../../vendor/autoload.php';

use Google\Auth\Cache\Item;
use Google\Auth\Cache\SysVCacheItemPool;
use Google\Auth\Cache\TypedItem;

$value = $argv[1];
// Use the same variableKey in the test.
$pool = new SysVCacheItemPool(['variableKey' => 99]);
if (\PHP_VERSION_ID >= 80000) {
    $item = new TypedItem('separate-process-item');
} else {
    $item = new Item('separate-process-item');
}
$item->set($value);
$pool->save($item);
