import pytest

from coincidence.crypto.keypair import BitcoinPrivateKey
from coincidence.crypto.utils import (
    RIPEMD160,
    ripemd160,
    sha1,
    sha256,
    sign_transaction,
    verify_signature,
)


def test_ripemd160_algorithm():
    ripemd = RIPEMD160()
    assert ripemd.name == "ripemd160"
    assert ripemd.digest_size == 20
    assert ripemd.block_size == 64


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        # test vectors from https://gist.github.com/Sajjon/95f0c72ca72f0b6985d550b80eff536d
        (
            b"",
            bytes.fromhex("9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        ),
        (
            b"a",
            bytes.fromhex("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        ),
        (
            b"abc",
            bytes.fromhex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        ),
        (
            b"message digest",
            bytes.fromhex("5d0689ef49d2fae572b881b123a85ffa21595f36"),
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            bytes.fromhex("f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            bytes.fromhex("12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            bytes.fromhex("b0e20b6e3116640286ed3a87a5713079b21f5189"),
        ),
    ],
)
def test_ripemd160_hash(data: bytes, expected: bytes):
    result = ripemd160(data)
    assert result == expected
    mutated = ripemd160(data + b" ")
    assert result != mutated


# pyright: reportImplicitStringConcatenation=false
@pytest.mark.parametrize(
    ("data", "expected"),
    [
        # test vectors from https://www.di-mgt.com.au/sha_testvectors.html
        (
            b"abc",
            bytes.fromhex(
                "ba7816bf 8f01cfea 414140de 5dae2223"
                "b00361a3 96177a9c b410ff61 f20015ad"
            ),
        ),
        (
            b"",
            bytes.fromhex(
                "e3b0c442 98fc1c14 9afbf4c8 996fb924"
                "27ae41e4 649b934c a495991b 7852b855"
            ),
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            bytes.fromhex(
                "248d6a61 d20638b8 e5c02693 0c3e6039"
                "a33ce459 64ff2167 f6ecedd4 19db06c1"
            ),
        ),
    ],
)
def test_sha256_hash(data: bytes, expected: bytes):
    result = sha256(data)
    assert result == expected
    mutated = sha256(data + b" ")
    assert result != mutated


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        # test vectors from https://www.di-mgt.com.au/sha_testvectors.html
        (
            b"abc",
            bytes.fromhex("a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d"),
        ),
        (
            b"",
            bytes.fromhex("da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709"),
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            bytes.fromhex("84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1"),
        ),
    ],
)
def test_sha1_hash(data: bytes, expected: bytes):
    result = sha1(data)
    assert result == expected
    mutated = sha1(data + b" ")
    assert result != mutated


def test_verify_signature():
    tx = bytes.fromhex(
        # test vector from https://en.bitcoin.it/wiki/OP_CHECKSIG
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25"
        "857fcd37040000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e"
        "97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9"
        "d4c03f999b8643f656b412a3acffffffff0200ca9a3b00000000434104ae1a62"
        "fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab3"
        "7397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac0028"
        "6bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b148"
        "2ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f"
        "999b8643f656b412a3ac0000000001000000"
    )
    pubkey = bytes.fromhex(
        "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a"
        "5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412"
        "a3"
    )
    signature = bytes.fromhex(
        "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab"
        "5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac46220822"
        "21a8768d1d09"
    )
    assert verify_signature(pubkey, signature, sha256(sha256(tx)))
    assert not verify_signature(pubkey, signature, sha256(sha256(tx + b" ")))


def test_sign_transaction():
    # Generate test key pair
    private_key = BitcoinPrivateKey.generate()
    public_key = private_key.public_key()

    # Test message
    test_msg = b"test message"
    msg_hash = sha256(sha256(test_msg))

    # Sign and verify
    signature = sign_transaction(msg_hash, private_key)
    assert verify_signature(public_key.sec, signature, msg_hash)

    # Verify signature is deterministic
    signature_2 = sign_transaction(msg_hash, private_key)
    assert signature == signature_2

    # Verify fails for modified message
    modified_hash = sha256(sha256(test_msg + b"modified"))
    assert not verify_signature(public_key.sec, signature, modified_hash)
