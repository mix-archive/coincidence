from typing import Literal, Self, final, override

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256K1,
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicKey,
    EllipticCurveSignatureAlgorithm,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256, Hash, HashAlgorithm

from . import bech32


class RIPEMD160(HashAlgorithm):
    @property
    @override
    def name(self):
        return "ripemd160"

    @property
    @override
    def digest_size(self):
        return 20

    @property
    @override
    def block_size(self):
        return 64


@final
class BitcoinPublicKey(EllipticCurvePublicKey):
    def __init__(self, base: EllipticCurvePublicKey) -> None:
        self.base = base

    @property
    @override
    def curve(self):
        return self.base.curve

    @property
    @override
    def key_size(self):
        return self.base.key_size

    @override
    def public_numbers(self):
        return self.base.public_numbers()

    @override
    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ):
        return self.base.public_bytes(encoding, format)

    @override
    def verify(
        self,
        signature: bytes,
        data: bytes,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ):
        return self.base.verify(signature, data, signature_algorithm)

    @override
    def __eq__(self, other: object) -> bool:
        return (
            self.hash == other.hash
            if isinstance(other, BitcoinPublicKey)
            else self.base == other
        )

    @property
    def hash(self):
        public_bytes = self.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        sha256_hash = Hash(SHA256())
        sha256_hash.update(public_bytes)
        ripemd160_hash = Hash(RIPEMD160())
        ripemd160_hash.update(sha256_hash.finalize())
        return ripemd160_hash.finalize()

    def address(
        self,
        network: Literal["test", "main"] = "test",
        variant: Literal["p2pkh", "p2sh", "bech32"] = "p2pkh",
    ) -> str:
        if variant in ("p2pkh", "p2sh"):
            version = {
                "main": {"p2pkh": b"\x00", "p2sh": b"\x05"},
                "test": {"p2pkh": b"\x6f", "p2sh": b"\xc4"},
            }[network][variant]
            return base58.b58encode_check(version + self.hash).decode("ascii")
        # https://en.bitcoin.it/wiki/Bech32
        result = bech32.encode(  # pyright:ignore[reportUnknownVariableType,reportUnknownMemberType]
            hrp={
                "main": "bc",
                "test": "tb",
            }[network],
            witver=0,
            witprog=self.hash,
        )
        if not isinstance(result, str):
            raise ValueError("Failed to encode address")  # noqa: TRY004
        return result


@final
class BitcoinPrivateKey(EllipticCurvePrivateKey):
    def __init__(self, base: EllipticCurvePrivateKey) -> None:
        self.base = base

    @classmethod
    def generate(cls) -> Self:
        generated = generate_private_key(SECP256K1())
        return cls(generated)

    @override
    def exchange(
        self,
        algorithm: ECDH,
        peer_public_key: EllipticCurvePublicKey,
    ) -> bytes:
        return self.base.exchange(algorithm, peer_public_key)

    @override
    def public_key(self) -> BitcoinPublicKey:
        return BitcoinPublicKey(self.base.public_key())

    @property
    @override
    def curve(self):
        return self.base.curve

    @property
    @override
    def key_size(self) -> int:
        return self.base.key_size

    @override
    def sign(
        self,
        data: bytes,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        return self.base.sign(data, signature_algorithm)

    @override
    def private_numbers(self) -> EllipticCurvePrivateNumbers:
        return self.base.private_numbers()

    @override
    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        return self.base.private_bytes(encoding, format, encryption_algorithm)
