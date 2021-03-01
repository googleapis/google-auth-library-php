<?php

namespace Google\Jwt;

class VerificationFailedException extends \UnexpectedValueException
{
    const EXPIRED = 1;
    const BEFORE_VALID = 2;
    const SIGNATURE_INVALID = 3;

    public function __construct(
        string $message,
        int $code,
        \Throwable $previous
    ) {
        if (!in_array($code, [
            self::EXPIRED,
            self::BEFORE_VALID,
            self::SIGNATURE_INVALID,
        ])) {
            throw new \InvalidArgumentException(
                'Invalid code for VerificationFailedException'
            );
        }
        parent::__construct($message, $code, $previous);
    }
}
