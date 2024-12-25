from io import BytesIO

import pytest

from coincidence.crypto.keypair import BitcoinPrivateKey

from .opcode import TransactionOpCode
from .script import (
    BaseTransactionScript,
    CoinbaseScript,
    CommonTransactionScript,
    PayToPublicKeyHashScript,
    PayToPublicKeyScript,
    ScriptDeserializationFlag,
    SignatureScript,
)


def test_transaction_script_serialization():
    script = CommonTransactionScript.from_commands([TransactionOpCode.OP_1, b"hello"])
    serialized = script.serialize()
    deserialized = BaseTransactionScript.deserialize(
        BytesIO(serialized), ScriptDeserializationFlag(0)
    )
    assert deserialized == script


def test_script_addition():
    script1 = CommonTransactionScript.from_commands([TransactionOpCode.OP_1])
    script2 = CommonTransactionScript.from_commands([TransactionOpCode.OP_2])
    combined = script1 + script2
    assert isinstance(combined, CommonTransactionScript)
    assert combined.commands == (TransactionOpCode.OP_1, TransactionOpCode.OP_2)


def test_common_script_bytecode():
    # Test empty bytecode
    script = CommonTransactionScript()
    assert script.bytecode == b""

    # Test with bytecode
    test_bytes = b"test123"
    script = CommonTransactionScript(test_bytes)
    assert script.bytecode == test_bytes

    # Test from_bytecode method
    script = CommonTransactionScript.from_bytecode(
        test_bytes, ScriptDeserializationFlag(0)
    )
    assert script
    assert script.bytecode == test_bytes

    # Test from_commands method
    commands = [TransactionOpCode.OP_1, b"test"]
    script = CommonTransactionScript.from_commands(commands)
    assert script.commands == tuple(commands)


def test_coinbase_script():
    script = CoinbaseScript(height=12345, remains=b"\x04test")
    serialized = script.serialize()
    deserialized = BaseTransactionScript.deserialize(
        BytesIO(serialized),
        ScriptDeserializationFlag.FROM_COINBASE | ScriptDeserializationFlag.FROM_INPUT,
    )
    assert isinstance(deserialized, CoinbaseScript)
    assert deserialized.height == 12345


@pytest.mark.parametrize(
    "compressed", [True, False], ids=["compressed", "uncompressed"]
)
def test_p2pk_script(*, compressed: bool):
    pk = BitcoinPrivateKey.generate(compressed=compressed).public_key()
    script = PayToPublicKeyScript(pk)
    serialized = script.serialize()
    deserialized = BaseTransactionScript.deserialize(
        BytesIO(serialized), ScriptDeserializationFlag.FROM_OUTPUT
    )
    assert isinstance(deserialized, PayToPublicKeyScript)
    assert deserialized.pubkey == pk


def test_p2pkh_script():
    hash160 = bytes([0] * 20)
    script = PayToPublicKeyHashScript(hash160)
    serialized = script.serialize()
    deserialized = BaseTransactionScript.deserialize(
        BytesIO(serialized), ScriptDeserializationFlag.FROM_OUTPUT
    )
    assert isinstance(deserialized, PayToPublicKeyHashScript)
    assert deserialized.hash160 == hash160


def test_signature_script():
    pk = BitcoinPrivateKey.generate().public_key()
    sig = bytes([0] * 71)
    script = SignatureScript(sig, pk)
    serialized = script.serialize()
    deserialized = BaseTransactionScript.deserialize(
        BytesIO(serialized), ScriptDeserializationFlag.FROM_INPUT
    )
    assert isinstance(deserialized, SignatureScript)
    assert deserialized.signature == sig
    assert deserialized.pubkey == pk
