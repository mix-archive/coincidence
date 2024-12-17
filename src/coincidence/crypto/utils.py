from typing import override

from cryptography.hazmat.primitives.hashes import SHA256, Hash, HashAlgorithm


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


def ripemd160(data: bytes) -> bytes:
    """Calculate the RIPEMD160 hash of the data."""
    h = Hash(RIPEMD160())
    h.update(data)
    return h.finalize()


def sha256(data: bytes) -> bytes:
    """Calculate the SHA-256 hash of the data."""
    h = Hash(SHA256())
    h.update(data)
    return h.finalize()
