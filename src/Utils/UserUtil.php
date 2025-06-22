<?php

namespace Jskorlol\JwtAuth\Utils;

use Jskorlol\JwtAuth\Interfaces\JwtUserInterface;

class UserUtil
{
    /**
     * Get user by identifier
     */
    public static function getUserByIdentifier(string|int $identifier): ?JwtUserInterface
    {
        $model = config('auth.providers.users.model');
        $instance = new $model;

        return $model::query()
            ->where($instance->getAuthIdentifierName(), $identifier)
            ->first();
    }
}
