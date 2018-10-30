<?php
/*
 * Copyright 2016 Google Inc.
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

namespace Google\Auth\Tests;

use Google\Auth\Cache\Clock;
use Google\Auth\Cache\Item;
use PHPUnit\Framework\TestCase;

class ItemTest extends TestCase
{
    public function getItem($key)
    {
        return new Item($key);
    }

    public function testGetsKey()
    {
        $key = 'item';

        $this->assertEquals($key, $this->getItem($key)->getKey());
    }

    public function testGetsNull()
    {
        $item = $this->getItem('item');

        $this->assertNull($item->get());
        $this->assertFalse($item->isHit());
    }

    public function testGetsValue()
    {
        $value = 'value';
        $item = $this->getItem('item');
        $item->set($value);

        $this->assertEquals('value', $item->get());
    }

    /**
     * @dataProvider values
     */
    public function testSetsValue($value)
    {
        $item = $this->getItem('item');
        $item->set($value);

        $this->assertEquals($value, $item->get());
    }

    public function values()
    {
        return [
            [1],
            [1.5],
            [true],
            [null],
            [new \DateTime()],
            [['test']],
            ['value']
        ];
    }

    public function testIsHit()
    {
        $item = $this->getItem('item');

        $this->assertFalse($item->isHit());

        $item->set('value');

        $this->assertTrue($item->isHit());
    }

    public function testExpiresAt()
    {
        $item = $this->getItem('item');
        $item->set('value');
        $item->expiresAt(new \DateTime('now + 1 hour'));

        $this->assertTrue($item->isHit());

        $item->expiresAt(null);

        $this->assertTrue($item->isHit());

        $item->expiresAt(new \DateTime('yesterday'));

        $this->assertFalse($item->isHit());
    }

    public function testExpiresAfter()
    {
        $item = $this->getItem('item');
        $item->set('value');
        $item->expiresAfter(30);

        $this->assertTrue($item->isHit());

        $item->expiresAfter(0);

        $this->assertFalse($item->isHit());

        $item->expiresAfter(new \DateInterval('PT30S'));

        $this->assertTrue($item->isHit());

        $item->expiresAfter(null);

        $this->assertTrue($item->isHit());
    }

    public function testItemExpirationDuringChangeOfDst()
    {
        $defaultTimezone = date_default_timezone_get();
        date_default_timezone_set('CET');

        $oneAm = new \DateTime('2018-10-28 01:00:00');
        $fiftyPastOne = new \DateTime('2018-10-28 01:50:00');
        $twoAm = new \DateTime('2018-10-28 02:00:00');

        Clock::setTime($oneAm);

        $key = 'item';
        $value = 'value';

        $item = new Item($key);
        $item->set($value);
        self::assertTrue($item->isHit());

        $expiresAfter = 1800;

        Clock::setTime($fiftyPastOne);
        $item->expiresAfter($expiresAfter);

        Clock::setTime($twoAm);

        self::assertGreaterThan(
            $expiresAfter,
            Clock::now()->getTimestamp() - $fiftyPastOne->getTimestamp(),
            'This proves that item should have expired.'
        );

        self::assertFalse($item->isHit());

        date_default_timezone_set($defaultTimezone);
    }
}
