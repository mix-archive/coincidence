from io import BytesIO

import pytest

from coincidence.crypto.keypair import BitcoinPrivateKey
from coincidence.crypto.utils import sign_transaction
from coincidence.transaction.types.script import (
    BaseTransactionScript,
    CommonTransactionScript,
    PayToPublicKeyHashScript,
    ScriptDeserializationFlag,
    SignatureScript,
)
from coincidence.transaction.types.transaction import (
    SignatureHashTypes,
    Transaction,
    TransactionInput,
    TransactionOutput,
)
from coincidence.transaction.utils import (
    TransactionValidationError,
    validate_transaction_scripts,
)


def test_transaction_signing():
    private_key = BitcoinPrivateKey.from_wif(
        "cSDHYsxxhkrzLDA9EoUV9bdmn6fGyspYN8cCGwsdXdUxsmSnWgQT"
    )

    tx_in = (
        TransactionInput(
            previous_transaction=bytes.fromhex(
                "0842d6084dddd67bdee2638f644d04ac576e046643c279a627fc1449bfc2a762"
            )[::-1],
            previous_index=1,
        ),
    )
    tx_out = (
        TransactionOutput(
            value=3000,
            script_pubkey=PayToPublicKeyHashScript.from_address(
                "mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv"
            ),
        ),
        TransactionOutput(
            value=1500,
            script_pubkey=PayToPublicKeyHashScript.from_address(
                "mgPyDZCBtc2eKGQJ5ZTATyJ6zPnGhSuGjP"
            ),
        ),
    )
    tx = Transaction(version=1, inputs=tx_in, outputs=tx_out, locktime=0)

    prev_script = CommonTransactionScript(
        bytes.fromhex("76a91409a5fbec0427555863af578496fca5426e18297288ac")
    )
    hash_ = tx.signature_hash(0, prev_script)
    signature = sign_transaction(hash_, private_key) + SignatureHashTypes.ALL.to_bytes(
        1, "big"
    )

    signed_tx = tx.replace_input_script(
        0, SignatureScript(signature, private_key.public_key())
    )
    assert (
        signed_tx.id.hex()
        == "af1324f6ab2b35d899164fd4aef74d1369dabddc702a03b75e5b28dd5603727b"
    )


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
            script_pubkey=PayToPublicKeyHashScript.from_address(
                "mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2"
            ),
        ),
        TransactionOutput(
            value=int(0.10 * 100000000),
            script_pubkey=PayToPublicKeyHashScript.from_address(
                "mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf"
            ),
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
    tx = Transaction.deserialize(BytesIO(serialized), ScriptDeserializationFlag(0))
    script_bytes = BaseTransactionScript.deserialize(
        BytesIO(bytes.fromhex("1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac")),
        ScriptDeserializationFlag(0),
    )

    # Test with raw bytes script
    assert validate_transaction_scripts(tx, [script_bytes])


def test_validate_transaction_scripts_fails_validation():
    tx = Transaction(
        version=1,
        inputs=(TransactionInput(b"x" * 32, 0, CommonTransactionScript()),),
        outputs=(),
        locktime=0,
    )
    invalid_script = CommonTransactionScript()  # Empty script will fail validation

    with pytest.raises(TransactionValidationError, match="Script validation failed"):
        _ = validate_transaction_scripts(tx, [invalid_script])
