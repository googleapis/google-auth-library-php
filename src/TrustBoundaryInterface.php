<?php

namespace Google\Auth;

/**
 * @internal
 */
interface TrustBoundaryInterface
{
    /**
     * @return bool
     */
    public function isTrustBoundarySuppressed();
}
