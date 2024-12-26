from io import BytesIO

from .opcode import TransactionOpCode
from .script import (
    BaseTransactionScript,
    CoinbaseScript,
    CommonTransactionScript,
    PayToPublicKeyHashScript,
    ScriptDeserializationFlag,
)
from .transaction import Transaction, TransactionInput, TransactionOutput


def test_transaction_input_serialization():
    script = CommonTransactionScript.from_commands([TransactionOpCode.OP_1, b"hello"])
    tx_input = TransactionInput(
        previous_transaction=b"\x00" * 32,
        previous_index=0,
        script_signature=script,
        sequence=0xFFFFFFFF,
    )
    serialized = tx_input.serialize()
    deserialized = TransactionInput.deserialize(
        BytesIO(serialized), ScriptDeserializationFlag(0)
    )
    assert deserialized == tx_input


def test_transaction_output_serialization():
    script = CommonTransactionScript.from_commands([TransactionOpCode.OP_1, b"hello"])
    tx_output = TransactionOutput(
        value=1000,
        script_pubkey=script,
    )
    serialized = tx_output.serialize()
    deserialized = TransactionOutput.deserialize(
        BytesIO(serialized), ScriptDeserializationFlag(0)
    )
    assert deserialized == tx_output


def test_transaction_serialization():
    script = CommonTransactionScript.from_commands([TransactionOpCode.OP_1, b"hello"])
    tx_input = TransactionInput(
        previous_transaction=b"\x00" * 32,
        previous_index=0,
        script_signature=script,
        sequence=0xFFFFFFFF,
    )
    tx_output = TransactionOutput(
        value=1000,
        script_pubkey=script,
    )
    transaction = Transaction(
        version=1,
        inputs=(tx_input,),
        outputs=(tx_output,),
        locktime=0,
    )
    assert hash(transaction) != id(transaction)
    serialized = transaction.serialize()
    deserialized = Transaction.deserialize(
        BytesIO(serialized), ScriptDeserializationFlag(0)
    )
    assert deserialized == transaction


def test_transaction_script_concatenation():
    script1 = CommonTransactionScript.from_commands([TransactionOpCode.OP_1, b"hello"])
    script2 = CommonTransactionScript.from_commands([TransactionOpCode.OP_2, b"world"])
    combined = script1 + script2
    assert tuple(combined.commands) == (
        TransactionOpCode.OP_1,
        b"hello",
        TransactionOpCode.OP_2,
        b"world",
    )
    assert isinstance(combined, BaseTransactionScript)
    assert id(combined) != id(script1)
    assert id(combined) != id(script2)


def test_transaction_realworld():
    """Real-world example of a Bitcoin transaction.

    ```text
    01000000 ................................... Version

    01 ......................................... Number of inputs
    |
    | 7b1eabe0209b1fe794124575ef807057
    | c77ada2138ae4fa8d6c4de0398a14f3f ......... Outpoint TXID
    | 00000000 ................................. Outpoint index number
    |
    | 49 ....................................... Bytes in sig. script: 73
    | | 48 ..................................... Push 72 bytes as data
    | | | 30450221008949f0cb400094ad2b5eb3
    | | | 99d59d01c14d73d8fe6e96df1a7150de
    | | | b388ab8935022079656090d7f6bac4c9
    | | | a94e0aad311a4268e082a725f8aeae05
    | | | 73fb12ff866a5f01 ..................... [Secp256k1][secp256k1] signature
    |
    | ffffffff ................................. Sequence number: UINT32_MAX

    01 ......................................... Number of outputs
    | f0ca052a01000000 ......................... Satoshis (49.99990000 BTC)
    |
    | 19 ....................................... Bytes in pubkey script: 25
    | | 76 ..................................... OP_DUP
    | | a9 ..................................... OP_HASH160
    | | 14 ..................................... Push 20 bytes as data
    | | | cbc20a7664f2f69e5355aa427045bc15
    | | | e7c6c772 ............................. PubKey hash
    | | 88 ..................................... OP_EQUALVERIFY
    | | ac ..................................... OP_CHECKSIG

    00000000 ................................... locktime: 0 (a block height)
    ```
    """
    input_ = TransactionInput(
        previous_transaction=b"\x7b\x1e\xab\xe0\x20\x9b\x1f\xe7\x94\x12\x45\x75\xef\x80\x70\x57\xc7\x7a\xda\x21\x38\xae\x4f\xa8\xd6\xc4\xde\x03\x98\xa1\x4f\x3f",
        previous_index=0,
        script_signature=BaseTransactionScript.deserialize(
            BytesIO(
                bytes.fromhex(
                    "49"  # pyright:ignore[reportImplicitStringConcatenation]
                    "48"
                    "30450221008949f0cb400094ad2b5eb3"
                    "99d59d01c14d73d8fe6e96df1a7150de"
                    "b388ab8935022079656090d7f6bac4c9"
                    "a94e0aad311a4268e082a725f8aeae05"
                    "73fb12ff866a5f01"
                )
            ),
            ScriptDeserializationFlag(0),
        ),
        sequence=0xFFFFFFFF,
    )
    assert "[...]" in repr(input_)

    output = TransactionOutput(
        value=49_999_900_00,
        script_pubkey=PayToPublicKeyHashScript(
            hash160=bytes.fromhex("cbc20a7664f2f69e5355aa427045bc15e7c6c772")
        ),
    )
    tx = Transaction(
        version=1,
        inputs=(input_,),
        outputs=(output,),
        locktime=0,
    )

    serialized = tx.serialize()
    assert serialized == (
        b"\x01\x00\x00\x00"
        b"\x01"
        b"\x7b\x1e\xab\xe0\x20\x9b\x1f\xe7\x94\x12\x45\x75\xef\x80\x70\x57\xc7\x7a\xda\x21\x38\xae\x4f\xa8\xd6\xc4\xde\x03\x98\xa1\x4f\x3f"
        b"\x00\x00\x00\x00"
        b"\x49"
        b"\x48"
        b"\x30\x45\x02\x21\x00\x89\x49\xf0\xcb\x40\x00\x94\xad\x2b\x5e\xb3\x99\xd5\x9d\x01\xc1\x4d\x73\xd8\xfe\x6e\x96\xdf\x1a\x71\x50\xde\xb3\x88\xab\x89\x35\x02\x20\x79\x65\x60\x90\xd7\xf6\xba\xc4\xc9\xa9\x4e\x0a\xad\x31\x1a\x42\x68\xe0\x82\xa7\x25\xf8\xae\xae\x05\x73\xfb\x12\xff\x86\x6a\x5f\x01"
        b"\xff\xff\xff\xff"
        b"\x01"
        b"\xf0\xca\x05\x2a\x01\x00\x00\x00"
        b"\x19"
        b"\x76\xa9\x14\xcb\xc2\x0a\x76\x64\xf2\xf6\x9e\x53\x55\xaa\x42\x70\x45\xbc\x15\xe7\xc6\xc7\x72\x88\xac"
        b"\x00\x00\x00\x00"
    )
    deserialized = Transaction.deserialize(
        BytesIO(serialized), ScriptDeserializationFlag(0)
    )
    assert deserialized == tx


def test_transaction_hash():
    serialized = bytes.fromhex(
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
    )
    tx = Transaction.deserialize(BytesIO(serialized), ScriptDeserializationFlag(0))
    assert (
        tx.id[::-1].hex()
        == "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4"
    )


def test_transaction_coinbase():
    # Create a coinbase transaction
    coinbase_input = TransactionInput(
        previous_transaction=bytes(32),  # All zeros
        previous_index=0xFFFFFFFF,
        script_signature=CoinbaseScript(114514),
    )

    coinbase_tx = Transaction(
        version=1,
        inputs=(coinbase_input,),
        outputs=(),
        locktime=0,
    )
    assert coinbase_tx.is_coinbase

    # Test non-coinbase transaction
    regular_input = TransactionInput(
        previous_transaction=bytes.fromhex("ff" * 32),  # Non-zero transaction hash
        previous_index=0,
        script_signature=CommonTransactionScript(),
    )
    regular_tx = Transaction(
        version=1,
        inputs=(regular_input,),
        outputs=(),
        locktime=0,
    )
    assert not regular_tx.is_coinbase

    # Test transaction with multiple inputs
    multi_input_tx = Transaction(
        version=1,
        inputs=(coinbase_input, regular_input),
        outputs=(),
        locktime=0,
    )
    assert not multi_input_tx.is_coinbase


def test_transaction_input_deserialize_flags():
    # Test coinbase flag handling
    coinbase_data = BytesIO(
        bytes(32)  # Previous transaction (all zeros)
        + (0xFFFFFFFF).to_bytes(4, "little")  # Previous index
        + b"\x00"  # Empty script
        + (0xFFFFFFFF).to_bytes(4, "little")  # Sequence
    )
    flags = ScriptDeserializationFlag.FROM_COINBASE
    tx_input = TransactionInput.deserialize(coinbase_data, flags)
    assert tx_input.previous_transaction == bytes(32)
    assert tx_input.previous_index == 0xFFFFFFFF

    # Test non-coinbase with coinbase flag
    regular_data = BytesIO(
        bytes.fromhex("ff" * 32)  # Previous transaction (non-zero)
        + (0).to_bytes(4, "little")  # Previous index
        + b"\x00"  # Empty script
        + (0xFFFFFFFF).to_bytes(4, "little")  # Sequence
    )
    flags = ScriptDeserializationFlag.FROM_COINBASE
    tx_input = TransactionInput.deserialize(regular_data, flags)
    assert type(tx_input.script_signature) is CommonTransactionScript
