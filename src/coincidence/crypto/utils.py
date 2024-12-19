from typing import override

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256K1,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, Hash, HashAlgorithm


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


def sha1(data: bytes) -> bytes:
    """Calculate the SHA-1 hash of the data."""
    h = Hash(SHA1())  # noqa: S303
    h.update(data)
    return h.finalize()


def verify_signature(pk: bytes, sig: bytes, data: bytes) -> bool:
    """Verify a signature using the public key.

    Args:
        pk (bytes): Public key in the SEC format
        sig (bytes): Signature in the DER format
        data (bytes): Data to verify, should be hash256

    """
    public_key = EllipticCurvePublicKey.from_encoded_point(SECP256K1(), pk)
    try:
        public_key.verify(sig, data, ECDSA(Prehashed(SHA256())))
    except InvalidSignature:
        return False
    return True
