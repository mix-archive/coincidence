from io import BytesIO

import pytest

from .common import varint
from .opcode import (
    InvalidOpcodeError,
    TransactionOpCode,
    dissect_script_bytecode,
    read_script_bytecode,
    serialize_command_bytes,
)


@pytest.mark.parametrize(
    ("count", "expected_prefix"),
    [
        (1, b"\x01"),
        (75, b"\x4b"),
        (76, b"\x4c\x4c"),
        (255, b"\x4c\xff"),
        (256, b"\x4d\x00\x01"),
        (65535, b"\x4d\xff\xff"),
        (65536, b"\x4e\x00\x00\x01\x00"),
    ],
)
def test_serialize_command_bytes(count: int, expected_prefix: bytes):
    data = b"a" * count
    serialized = serialize_command_bytes(data)
    assert serialized.startswith(expected_prefix)
    assert serialized[len(expected_prefix) :] == data

    deserialized = dissect_script_bytecode(serialized)
    assert len(deserialized) == 1
    assert deserialized[0] == data


def test_invalid_opcode_deserialize():
    # Create an invalid script with an unknown opcode
    invalid_script = varint(1).serialize() + bytes([0xFF])  # 0xFF is not a valid opcode
    with pytest.raises(InvalidOpcodeError, match="Invalid opcode: 255"):
        _ = dissect_script_bytecode(read_script_bytecode(BytesIO(invalid_script)))


def test_transaction_opcode_serialization():
    opcode = TransactionOpCode.OP_1
    serialized = opcode.serialize()
    assert serialized == b"\x51"
