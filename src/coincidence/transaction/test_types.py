from io import BytesIO

import pytest

from coincidence.transaction.types import (
    Transaction,
    TransactionInput,
    TransactionOpCode,
    TransactionOutput,
    TransactionScript,
    serialize_command_bytes,
    varint,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0x00, b"\x00"),
        (0xFC, b"\xfc"),
        (0xDEAD, b"\xfd\xad\xde"),
        (0xFFFF, b"\xfd\xff\xff"),
        (0xDEADBEEF, b"\xfe\xef\xbe\xad\xde"),
        (0xFFFFFFFF, b"\xfe\xff\xff\xff\xff"),
        (0xDEADBEEFDEADBEEF, b"\xff\xef\xbe\xad\xde\xef\xbe\xad\xde"),
    ],
)
def test_varint_serialization(value: int, expected: bytes):
    serialized = varint(value).serialize()
    assert serialized == expected
    deserialized = varint.deserialize(BytesIO(serialized))
    assert deserialized == value


def test_transaction_opcode_serialization():
    opcode = TransactionOpCode.OP_1
    serialized = opcode.serialize()
    assert serialized == b"\x51"


def test_serialize_command_bytes():
    data = b"hello"
    serialized = serialize_command_bytes(data)
    assert serialized == b"\x05hello"


def test_transaction_script_serialization():
    script = TransactionScript(commands=(TransactionOpCode.OP_1, b"hello"))
    serialized = script.serialize()
    deserialized = TransactionScript.deserialize(BytesIO(serialized))
    assert deserialized == script


def test_transaction_input_serialization():
    script = TransactionScript(commands=(TransactionOpCode.OP_1, b"hello"))
    tx_input = TransactionInput(
        previous_transaction=b"\x00" * 32,
        previous_index=0,
        script_signature=script,
        sequence=0xFFFFFFFF,
    )
    serialized = tx_input.serialize()
    deserialized = TransactionInput.deserialize(BytesIO(serialized))
    assert deserialized == tx_input


def test_transaction_output_serialization():
    script = TransactionScript(commands=(TransactionOpCode.OP_1, b"hello"))
    tx_output = TransactionOutput(
        value=1000,
        script_pubkey=script,
    )
    serialized = tx_output.serialize()
    deserialized = TransactionOutput.deserialize(BytesIO(serialized))
    assert deserialized == tx_output


def test_transaction_serialization():
    script = TransactionScript(commands=(TransactionOpCode.OP_1, b"hello"))
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
    serialized = transaction.serialize()
    deserialized = Transaction.deserialize(BytesIO(serialized))
    assert deserialized == transaction


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
        script_signature=TransactionScript(
            commands=(
                b"\x30\x45\x02\x21\x00\x89\x49\xf0\xcb\x40\x00\x94\xad\x2b\x5e\xb3\x99\xd5\x9d\x01\xc1\x4d\x73\xd8\xfe\x6e\x96\xdf\x1a\x71\x50\xde\xb3\x88\xab\x89\x35\x02\x20\x79\x65\x60\x90\xd7\xf6\xba\xc4\xc9\xa9\x4e\x0a\xad\x31\x1a\x42\x68\xe0\x82\xa7\x25\xf8\xae\xae\x05\x73\xfb\x12\xff\x86\x6a\x5f\x01",
            ),
        ),
        sequence=0xFFFFFFFF,
    )
    output = TransactionOutput(
        value=49_999_900_00,
        script_pubkey=TransactionScript(
            commands=(
                TransactionOpCode.OP_DUP,
                TransactionOpCode.OP_HASH160,
                b"\xcb\xc2\x0a\x76\x64\xf2\xf6\x9e\x53\x55\xaa\x42\x70\x45\xbc\x15\xe7\xc6\xc7\x72",
                TransactionOpCode.OP_EQUALVERIFY,
                TransactionOpCode.OP_CHECKSIG,
            ),
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
    deserialized = Transaction.deserialize(BytesIO(serialized))
    assert deserialized == tx
