from io import BytesIO

import pytest

from coincidence.transaction.types import (
    Transaction,
    TransactionInput,
    TransactionOpCode,
    TransactionOutput,
    TransactionScript,
)
from coincidence.transaction.utils import (
    TransactionValidationError,
    p2pkh_script,
    validate_transaction_scripts,
)


def test_p2pkh_script_from_address():
    # Test creating P2PKH from a base58 address string
    address = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    script = p2pkh_script(address)
    expected_hash160 = bytes.fromhex("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31")

    assert script.commands[0] == TransactionOpCode.OP_DUP
    assert script.commands[1] == TransactionOpCode.OP_HASH160
    assert script.commands[2] == expected_hash160
    assert script.commands[3] == TransactionOpCode.OP_EQUALVERIFY
    assert script.commands[4] == TransactionOpCode.OP_CHECKSIG


def test_p2pkh_script_from_hash160():
    # Test creating P2PKH from raw hash160 bytes
    hash160 = bytes.fromhex("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31")
    script = p2pkh_script(hash160)

    assert script.commands[0] == TransactionOpCode.OP_DUP
    assert script.commands[1] == TransactionOpCode.OP_HASH160
    assert script.commands[2] == hash160
    assert script.commands[3] == TransactionOpCode.OP_EQUALVERIFY
    assert script.commands[4] == TransactionOpCode.OP_CHECKSIG


def test_p2pkh_script():
    tx_in = (
        TransactionInput(
            previous_transaction=bytes.fromhex(
                "0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299"
            )[::-1],
            previous_index=13,
        ),
    )
    tx_outs = (
        TransactionOutput(
            value=int(0.33 * 100000000),
            script_pubkey=p2pkh_script("mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2"),
        ),
        TransactionOutput(
            value=int(0.10 * 100000000),
            script_pubkey=p2pkh_script("mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf"),
        ),
    )
    tx = Transaction(
        version=1,
        inputs=tx_in,
        outputs=tx_outs,
        locktime=0,
    )
    assert (
        tx.id.hex()
        == "cd30a8da777d28ef0e61efe68a9f7c559c1d3e5bcd7b265c850ccb4068598d11"
    )


def test_validate_transaction_scripts_mismatched_inputs():
    tx = Transaction(
        version=1, inputs=(TransactionInput(b"x" * 32, 0),), outputs=(), locktime=0
    )

    with pytest.raises(
        TransactionValidationError,
        match="Number of pubkey scripts does not match number of inputs",
    ):
        _ = validate_transaction_scripts(tx, [])


def test_validate_transaction_scripts_raw_bytes():
    serialized = bytes.fromhex(
        "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303"  # pyright: ignore[reportImplicitStringConcatenation]
        "c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746f"
        "a5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f5"
        "6100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f"
        "89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef010000"
        "00001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800"
        "000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac1943"
        "0600"
    )
    tx = Transaction.deserialize(BytesIO(serialized))
    script_bytes = bytes.fromhex("1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac")

    # Test with raw bytes script
    assert validate_transaction_scripts(tx, [script_bytes])


def test_validate_transaction_scripts_fails_validation():
    tx = Transaction(
        version=1,
        inputs=(TransactionInput(b"x" * 32, 0, TransactionScript()),),
        outputs=(),
        locktime=0,
    )
    invalid_script = TransactionScript()  # Empty script will fail validation

    with pytest.raises(TransactionValidationError, match="Script validation failed"):
        _ = validate_transaction_scripts(tx, [invalid_script])


def test_transaction_signature_hash():
    serialized = bytes.fromhex(
        "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303"  # pyright: ignore[reportImplicitStringConcatenation]
        "c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746f"
        "a5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f5"
        "6100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f"
        "89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef010000"
        "00001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800"
        "000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac1943"
        "0600"
    )
    tx = Transaction.deserialize(BytesIO(serialized))
    serialized_script = bytes.fromhex(
        "1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac"
    )
    former_script = TransactionScript.deserialize(BytesIO(serialized_script))
    signature_hash = tx.signature_hash(0, former_script)
    assert signature_hash == bytes.fromhex(
        "27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6"
    )

    assert validate_transaction_scripts(tx, [former_script])
