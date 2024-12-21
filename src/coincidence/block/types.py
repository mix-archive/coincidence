import dataclasses
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import IO, Self

from coincidence.crypto import sha256


class VersionLegacy(IntEnum):
    ORIGINAL = 1
    """Original version of the block header, starting from height 0"""
    BIP34 = 2
    """BIP34: Height in coinbase, starting from height 227,931"""
    BIP66 = 3
    """BIP66: Strict DER signatures, starting from height 363,725"""
    BIP65 = 4
    """BIP65: OP_CHECKLOCKTIMEVERIFY, starting from height 388,381"""


class VersionBitFlags(IntFlag):
    BIP112 = 1 << 0
    """BIP112: CHECKSEQUENCEVERIFY, starting from height 419,328"""
    BIP141 = 1 << 1
    """BIP141: Segregated Witness, starting from height 481,824"""
    BIP341 = 1 << 2
    """BIP341: Taproot, starting from height 709,632"""


@dataclass(frozen=True)
class Block:
    version: int
    previous_block: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int

    @property
    def features(self):
        if not self.version & 0x20000000:
            return VersionLegacy(self.version)
        recognizable_flags = VersionBitFlags(0)
        for flag in VersionBitFlags:
            if self.version & flag:
                recognizable_flags |= flag
        return recognizable_flags

    @property
    def hash(self) -> bytes:
        return sha256(sha256(self.serialize()))[::-1]

    @property
    def target(self) -> bytes:
        exponent = self.bits >> 24
        coefficient = self.bits & 0x00FFFFFF
        return (coefficient << (8 * (exponent - 3))).to_bytes(32, "big")

    def replace_nonce(self, nonce: int) -> Self:
        return dataclasses.replace(self, nonce=nonce)

    def serialize(self) -> bytes:
        return (
            self.version.to_bytes(4, "little")
            + self.previous_block
            + self.merkle_root
            + self.timestamp.to_bytes(4, "little")
            + self.bits.to_bytes(4, "little")
            + self.nonce.to_bytes(4, "little")
        )

    @classmethod
    def deserialize(cls, data: IO[bytes]) -> Self:
        version = int.from_bytes(data.read(4), "little")
        previous_block = data.read(32)
        merkle_root = data.read(32)
        timestamp = int.from_bytes(data.read(4), "little")
        bits = int.from_bytes(data.read(4), "little")
        nonce = int.from_bytes(data.read(4), "little")
        return cls(version, previous_block, merkle_root, timestamp, bits, nonce)
