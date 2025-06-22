<?php

namespace Jskorlol\JwtAuth\Enums;

enum AlgorithmEnum: string
{
    case HS256 = 'HS256';
    case HS384 = 'HS384';
    case HS512 = 'HS512';

    public function getAlgo(): string
    {
        return match ($this) {
            self::HS256 => 'sha256',
            self::HS384 => 'sha384',
            self::HS512 => 'sha512',
        };
    }
}
