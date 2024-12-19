import base58
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    ECDSA,
    SECP256K1,
)
from cryptography.hazmat.primitives.hashes import SHA256

from coincidence.crypto.keypair import BitcoinPrivateKey, BitcoinPublicKey


def test_key_generation():
    private_key = BitcoinPrivateKey.generate()
    assert isinstance(private_key, BitcoinPrivateKey)
    assert private_key.curve.name == SECP256K1().name
    assert private_key.key_size == 256


def test_public_key():
    private_key = BitcoinPrivateKey.generate()
    public_key = private_key.public_key()
    assert isinstance(public_key, BitcoinPublicKey)
    assert public_key.curve.name == SECP256K1().name
    assert public_key.key_size == 256


def test_key_exchange():
    alice_private = BitcoinPrivateKey.generate()
    bob_private = BitcoinPrivateKey.generate()

    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()

    shared_key1 = alice_private.exchange(ECDH(), bob_public)
    shared_key2 = bob_private.exchange(ECDH(), alice_public)

    assert shared_key1 == shared_key2


def test_key_signing():
    private_key = BitcoinPrivateKey.generate()
    public_key = private_key.public_key()

    data = b"Hello, World!"
    signature = private_key.sign(data, ECDSA(SHA256()))
    public_key.verify(signature, data, ECDSA(SHA256()))

    mangled_data = b"Hello, World?"
    with pytest.raises(InvalidSignature):
        public_key.verify(signature, mangled_data, ECDSA(SHA256()))


def test_public_key_equality():
    private_key = BitcoinPrivateKey.generate()
    public_key1 = private_key.public_key()
    public_key2 = private_key.public_key()
    assert public_key1 == public_key2


def test_address_generation():
    private_key = BitcoinPrivateKey.generate()
    public_key = private_key.public_key()

    # Test P2PKH addresses
    testnet_addr = public_key.address(network="test", variant="p2pkh")
    assert testnet_addr.startswith(("m", "n"))

    mainnet_addr = public_key.address(network="main", variant="p2pkh")
    assert mainnet_addr.startswith("1")

    # Test P2SH addresses
    testnet_p2sh = public_key.address(network="test", variant="p2sh")
    assert testnet_p2sh.startswith("2")

    mainnet_p2sh = public_key.address(network="main", variant="p2sh")
    assert mainnet_p2sh.startswith("3")

    # Test public numbers
    public_numbers = public_key.public_numbers()
    assert public_numbers.x.to_bytes(32, "big") in base58.b58decode(
        public_key.address(variant="p2pk")
    )
    assert public_numbers.y.to_bytes(32, "big") in base58.b58decode(
        public_key.address(variant="p2pk")
    )

    # Test Bech32 addresses
    testnet_bech32 = public_key.address(network="test", variant="bech32")
    assert testnet_bech32.startswith("tb1")

    mainnet_bech32 = public_key.address(network="main", variant="bech32")
    assert mainnet_bech32.startswith("bc1")


def test_key_serialization():
    private_key = BitcoinPrivateKey.generate()
    public_key = private_key.public_key()

    # Test public key serialization
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    assert isinstance(public_bytes, bytes)
    assert len(public_bytes) == 65  # Uncompressed public key is 65 bytes

    # Test private key serialization
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    assert isinstance(private_bytes, bytes)
    assert private_bytes.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert private_bytes.endswith(b"-----END PRIVATE KEY-----\n")


def test_wif_generation():
    private_key = BitcoinPrivateKey.generate()

    # Test WIF for testnet
    testnet_wif = private_key.wif(network="test")
    assert isinstance(testnet_wif, str)
    assert testnet_wif.startswith(("9", "c"))

    # Test WIF for mainnet
    mainnet_wif = private_key.wif(network="main")
    assert isinstance(mainnet_wif, str)
    assert mainnet_wif.startswith(("5", "K", "L"))
