<?php

namespace Jskorlol\JwtAuth;

use Jskorlol\JwtAuth\Data\Jwt;
use Jskorlol\JwtAuth\Exceptions\InvalidTokenStructure;
use Jskorlol\JwtAuth\Exceptions\UnsupportedCryptAlgorithm;
use Jskorlol\JwtAuth\Services\AuthService;

final class JwtAuthManager
{
    public function __construct(
        private readonly AuthService $authService
    ) {}

    /**
     * Manually refresh the current JWT token with updated user props
     *
     * @param  bool  $force  Force refresh without checking cache
     * @return string|null The new token or null if refresh failed
     */
    public function refreshToken(bool $force = true): ?string
    {
        // Get current token from request
        $token = request()->bearerToken();
        if (! $token) {
            return null;
        }

        try {
            // Decode the current JWT
            $jwt = Jwt::decode($token);

            // Force refresh with preemptive Flag to get updated props
            $refreshedJwt = $this->authService->handleAutoRefresh($jwt, true, $force);

            if (! $refreshedJwt) {
                return null;
            }

            return $refreshedJwt->encode();
        } catch (InvalidTokenStructure|UnsupportedCryptAlgorithm $e) {
            return null;
        }
    }
}
