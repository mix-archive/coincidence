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
    derive_private_key,
    generate_private_key,
)

from .bech32 import encode as bech32_encode  # pyright:ignore[reportUnknownVariableType]
from .utils import ripemd160, sha256


@final
class BitcoinPublicKey(EllipticCurvePublicKey):
    def __init__(self, base: EllipticCurvePublicKey, *, compressed: bool = True):
        self.base = base
        self.compressed = compressed

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
            self.public_numbers() == other.base.public_numbers()
            if isinstance(other, BitcoinPublicKey)
            else self.base == other
        )

    @property
    def sec(self) -> bytes:
        """Return the SEC representation of the public key."""
        return self.public_bytes(
            encoding=serialization.Encoding.X962,
            format=(
                serialization.PublicFormat.CompressedPoint
                if self.compressed
                else serialization.PublicFormat.UncompressedPoint
            ),
        )

    @property
    def hash160(self) -> bytes:
        """Return the RIPEMD160 hash of the SHA256 hash of the public key."""
        return ripemd160(sha256(self.sec))

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
            return base58.b58encode_check(version + self.hash160).decode("ascii")
        # https://en.bitcoin.it/wiki/Bech32
        result = bech32_encode(  # pyright:ignore[reportUnknownVariableType]
            hrp={
                "main": "bc",
                "test": "tb",
            }[network],
            witver=0,
            witprog=self.hash160,
        )
        if not isinstance(result, str):  # pragma: no cover
            raise ValueError("Failed to encode address")  # noqa: TRY004
        return result


@final
class BitcoinPrivateKey(EllipticCurvePrivateKey):
    def __init__(
        self, base: EllipticCurvePrivateKey, *, compressed: bool = True
    ) -> None:
        self.base = base
        self.compressed = compressed

    @classmethod
    def generate(cls, *, compressed: bool = True) -> Self:
        generated = generate_private_key(SECP256K1())
        return cls(generated, compressed=compressed)

    @override
    def exchange(
        self,
        algorithm: ECDH,
        peer_public_key: EllipticCurvePublicKey,
    ) -> bytes:
        pk = EllipticCurvePublicKey.from_encoded_point(
            SECP256K1(),
            peer_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            ),
        )
        return self.base.exchange(algorithm, pk)

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
    def __eq__(self, other: object, /) -> bool:
        return (
            self.base.private_numbers() == other.base.private_numbers()
            if isinstance(other, BitcoinPrivateKey)
            else self.base == other
        )

    @override
    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        return self.base.private_bytes(encoding, format, encryption_algorithm)

    def wif(self, network: Literal["test", "main"] = "test") -> str:
        version = {
            "main": b"\x80",
            "test": b"\xef",
        }[network]
        return base58.b58encode_check(
            version
            + self.private_numbers().private_value.to_bytes(32, "big")
            + (b"\x01" if self.compressed else b"")
        ).decode()

    @classmethod
    def from_wif(cls, wif: str) -> Self:
        raw = base58.b58decode_check(wif)
        version, pk = raw[0], raw[1:]
        if version not in (0x80, 0xEF):
            raise ValueError("Invalid WIF version byte")
        match len(pk):
            case 32:
                compressed = False
            case 33:
                compressed = True
                pk = pk[:-1]
            case _:
                raise ValueError("Invalid private key length")
        sk = derive_private_key(int.from_bytes(pk, "big"), SECP256K1())
        return cls(sk, compressed=compressed)
