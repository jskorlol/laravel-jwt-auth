<?php

namespace Jskorlol\JwtAuth\Data;

use Jskorlol\JwtAuth\Enums\AlgorithmEnum;
use Jskorlol\JwtAuth\Exceptions\InvalidTokenStructure;
use Jskorlol\JwtAuth\Exceptions\UnsupportedCryptAlgorithm;
use Jskorlol\JwtAuth\Utils\StringUtil;

class JwtHeader extends AbstractJwtComponent
{
    public function __construct(
        public readonly AlgorithmEnum $algorithm,
        public readonly ?string $kid = null,
        public readonly ?string $typ = null,
    ) {}

    /**
     * @throws InvalidTokenStructure
     * @throws UnsupportedCryptAlgorithm
     */
    public static function decode(string $string): self
    {
        $data = self::decodeString($string);
        $algorithm = AlgorithmEnum::tryFrom($data['alg']);
        if ($algorithm === null) {
            throw new UnsupportedCryptAlgorithm($data['alg']);
        }

        $instance = new self(
            $algorithm,
            $data['kid'] ?? null,
            $data['typ'] ?? null
        );
        $instance->setSource($string);

        return $instance;
    }

    public function encode(): string
    {
        $data = [
            'alg' => $this->algorithm->value,
        ];
        if ($this->kid !== null) {
            $data['kid'] = $this->kid;
        }
        if ($this->typ !== null) {
            $data['typ'] = $this->typ;
        }

        return StringUtil::encode(json_encode($data));
    }
}
