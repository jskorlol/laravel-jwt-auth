<?php

namespace Jskorlol\JwtAuth\Traits;

use Illuminate\Support\Str;
use Jskorlol\JwtAuth\Data\Jwt;
use Jskorlol\JwtAuth\Data\JwtHeader;
use Jskorlol\JwtAuth\Data\JwtPayload;
use Jskorlol\JwtAuth\Data\ResponseTokenData;
use Jskorlol\JwtAuth\Enums\AlgorithmEnum;
use Jskorlol\JwtAuth\Interfaces\JwtUserInterface;
use Jskorlol\JwtAuth\Services\AuthService;

trait JwtTrait
{
    public function generateJwt(?int $lifetime = null): ResponseTokenData
    {
        $user = $this->getJwtUser();
        $lifetimeSeconds = $lifetime ?? (int) config('jwt-auth.access_token.lifetime', 3600);
        $expiresAt = now()->addSeconds($lifetimeSeconds);
        $algorithm = AlgorithmEnum::from(config('jwt-auth.algorithm', 'HS256'));

        $customProps = method_exists($user, 'getJwtProps') ? $user->getJwtProps() : [];

        $token = new Jwt(
            new JwtHeader($algorithm),
            new JwtPayload(
                jti: $user->getAuthIdentifier().':'.Str::random(32),
                iat: now()->timestamp,
                exp: $expiresAt->timestamp,
                sub: $user->getAuthIdentifier(),
                iss: null,
                aud: null,
                props: ! empty($customProps) ? $customProps : null
            )
        );

        return app(AuthService::class)->generateAccessToken($user, $token, $lifetimeSeconds);
    }

    private function getJwtUser(): JwtUserInterface
    {
        return $this;
    }
}
