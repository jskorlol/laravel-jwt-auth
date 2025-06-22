<?php

namespace Jskorlol\JwtAuth\Data;

use Jskorlol\JwtAuth\Exceptions\InvalidTokenStructure;
use Jskorlol\JwtAuth\Exceptions\UnsupportedCryptAlgorithm;
use Jskorlol\JwtAuth\Utils\Crypto;

class Jwt
{
    private ?string $crc;

    public function __construct(public readonly JwtHeader $header, public readonly JwtPayload $payload) {}

    /**
     * @throws InvalidTokenStructure
     * @throws UnsupportedCryptAlgorithm
     */
    public static function decode(string $token): self
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidTokenStructure;
        }

        return new self(
            JwtHeader::decode($parts[0]),
            JwtPayload::decode($parts[1])
        )->setCrc($parts[2]);
    }

    public function encode(): string
    {
        $header = $this->header->encode();
        $payload = $this->payload->encode();
        $crypto = app(Crypto::class);

        return $header.'.'.$payload.'.'.$crypto->encode($this->header->algorithm, $header.'.'.$payload);
    }

    public function getCrc(): ?string
    {
        return $this->crc;
    }

    public function setCrc(?string $crc): self
    {
        $this->crc = $crc;

        return $this;
    }
}
