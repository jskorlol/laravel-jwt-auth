<?php

namespace Jskorlol\JwtAuth\Interfaces;

use Jskorlol\JwtAuth\Data\Jwt;
use Jskorlol\JwtAuth\Data\RefreshTokenData;

interface RefreshTokenStorageInterface
{
    /**
     * Get user by refresh token
     */
    public function getUser(string $refreshToken): ?JwtUserInterface;

    /**
     * Get refresh token data
     */
    public function getData(string $refreshToken): ?RefreshTokenData;

    /**
     * Create a new refresh token
     */
    public function create(JwtUserInterface $user, string $refreshToken, int $expiresAt, int $lifetime): void;

    /**
     * Delete refresh token
     */
    public function delete(JwtUserInterface $user, string $refreshToken): void;

    /**
     * Store auto-refreshed token in cache
     */
    public function storeAutoRefreshedToken(Jwt $originalJwt, Jwt $refreshedJwt, int $ttl): void;

    /**
     * Get cached auto-refreshed token
     */
    public function getAutoRefreshedToken(Jwt $jwt): ?string;

    /**
     * Mark auto-refresh as completed for the token
     */
    public function markAutoRefreshCompleted(Jwt $jwt): void;

    /**
     * Check if auto-refresh has been processed for this token
     */
    public function hasAutoRefreshBeenProcessed(Jwt $jwt): bool;
}
