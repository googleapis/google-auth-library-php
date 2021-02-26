<?php
/*
 * Copyright 2020 Google LLC
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

declare(strict_types=1);

namespace Google\Http\Promise;

use GuzzleHttp\Promise\PromiseInterface as GuzzlePromiseInterface;

class GuzzlePromise implements PromiseInterface
{
    /**
     * @var \GuzzleHttp\Promise\PromiseInterface
     */
    private $promise;

    /**
     * @param \GuzzleHttp\Promise\PromiseInterface $promise
     */
    public function __construct(GuzzlePromiseInterface $promise)
    {
        $this->promise = $promise;
    }

    /**
     * Appends fulfillment and rejection handlers to the promise, and returns
     * a new promise resolving to the return value of the called handler.
     *
     * @param callable $onFulfilled invoked when the promise fulfills
     * @param callable $onRejected  invoked when the promise is rejected
     *
     * @return PromiseInterface
     */
    public function then(
        callable $onFulfilled = null,
        callable $onRejected = null
    ): PromiseInterface {
        return $this->promise->then($onFulfilled, $onRejected);
    }

    /**
     * Appends a rejection handler callback to the promise, and returns a new
     * promise resolving to the return value of the callback if it is called,
     * or to its original fulfillment value if the promise is instead
     * fulfilled.
     *
     * @param callable $onRejected invoked when the promise is rejected
     *
     * @return PromiseInterface
     */
    public function otherwise(callable $onRejected): PromiseInterface
    {
        return $this->promise->otherwise($onRejected);
    }

    /**
     * Get the state of the promise ("pending", "rejected", or "fulfilled").
     *
     * The three states can be checked against the constants defined on
     * PromiseInterface: PENDING, FULFILLED, and REJECTED.
     *
     * @return string
     */
    public function getState(): string
    {
        return $this->promise->getState();
    }

    /**
     * Resolve the promise with the given value.
     *
     * @param mixed $value
     *
     * @throws \RuntimeException if the promise is already resolved
     */
    public function resolve($value)
    {
        return $this->promise->resolve($value);
    }

    /**
     * Reject the promise with the given reason.
     *
     * @param mixed $reason
     *
     * @throws \RuntimeException if the promise is already resolved
     */
    public function reject($reason)
    {
        return $this->promise->reject($reason);
    }

    /**
     * Cancels the promise if possible.
     *
     * @see https://github.com/promises-aplus/cancellation-spec/issues/7
     */
    public function cancel()
    {
        return $this->promise->cancel();
    }

    /**
     * Waits until the promise completes if possible.
     *
     * Pass $unwrap as true to unwrap the result of the promise, either
     * returning the resolved value or throwing the rejected exception.
     *
     * If the promise cannot be waited on, then the promise will be rejected.
     *
     * @param bool $unwrap
     *
     * @throws \LogicException if the promise has no wait function or if the
     *                         promise does not settle after waiting
     *
     * @return mixed
     */
    public function wait(bool $unwrap = true)
    {
        return $this->promise->wait($unwrap);
    }
}
