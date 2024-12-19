from dataclasses import dataclass
from enum import IntEnum
from io import BytesIO
from typing import IO, Self


class varint(int):  # noqa:N801
    r"""Variable-length integer.

    This class is used to represent a variable-length integer in the Bitcoin
    protocol. It is a subclass of the built-in `int` class, so it can be used
    like a regular integer. The value of the integer is stored in the `value`
    attribute.

    The `serialize` method is used to serialize the integer into a sequence of
    bytes. The `deserialize` method is used to deserialize a sequence of bytes
    into an integer.

    Example:
        >>> value = varint(0x12345678)
        >>> value.serialize()
        b'\xfd\x78\x56\x34\x12'
        >>> varint.deserialize(b'\xfd\x78\x56\x34\x12')
        varint(0x12345678)

    Reference: https://developer.bitcoin.org/reference/transactions.html#compactsize-unsigned-integers

    """

    def serialize(self):
        """Serialize the variable-length integer into a sequence of bytes."""
        if (bit_length := self.bit_length()) <= 8 and self < 0xFD:  # noqa: PLR2004
            return self.to_bytes(1, "little")
        if bit_length <= 16:  # noqa: PLR2004
            return b"\xfd" + self.to_bytes(2, "little")
        if bit_length <= 32:  # noqa: PLR2004
            return b"\xfe" + self.to_bytes(4, "little")
        return b"\xff" + self.to_bytes(8, "little")

    @classmethod
    def deserialize(cls, data: IO[bytes]):
        """Deserialize a sequence of bytes into a variable-length integer."""
        match data.read(1):
            case b"\xfd":
                return cls.from_bytes(data.read(2), "little")
            case b"\xfe":
                return cls.from_bytes(data.read(4), "little")
            case b"\xff":
                return cls.from_bytes(data.read(8), "little")
            case byte:
                return cls.from_bytes(byte, "little")


class TransactionOpCode(IntEnum):
    """Transaction script opcodes.

    Reference:
        - https://developer.bitcoin.org/reference/transactions.html#opcodes
        - https://github.com/bitcoin/bitcoin/blob/master/src/script/script.h

    """

    # Push value
    OP_0 = 0x00
    OP_FALSE = OP_0
    OP_PUSHDATA1 = 0x4C
    OP_PUSHDATA2 = 0x4D
    OP_PUSHDATA4 = 0x4E
    OP_1NEGATE = 0x4F
    OP_TRUE = 0x51
    OP_1 = OP_TRUE
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5A
    OP_11 = 0x5B
    OP_12 = 0x5C
    OP_13 = 0x5D
    OP_14 = 0x5E
    OP_15 = 0x5F
    OP_16 = 0x60

    # Control flow
    OP_NOP = 0x61
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6A

    # Stack
    OP_TOALTSTACK = 0x6B
    OP_FROMALTSTACK = 0x6C
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7A
    OP_ROT = 0x7B
    OP_SWAP = 0x7C
    OP_TUCK = 0x7D
    OP_2DROP = 0x6D
    OP_2DUP = 0x6E
    OP_3DUP = 0x6F
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72

    # Splice
    OP_CAT = 0x7E
    OP_SUBSTR = 0x7F
    OP_LEFT = 0x80
    OP_RIGHT = 0x81
    OP_SIZE = 0x82

    # Bitwise logic
    OP_INVERT = 0x83
    OP_AND = 0x84
    OP_OR = 0x85
    OP_XOR = 0x86
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88

    # Arithmetic
    OP_1ADD = 0x8B
    OP_1SUB = 0x8C
    OP_2MUL = 0x8D
    OP_2DIV = 0x8E
    OP_NEGATE = 0x8F
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92
    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95
    OP_DIV = 0x96
    OP_MOD = 0x97
    OP_LSHIFT = 0x98
    OP_RSHIFT = 0x99
    OP_BOOLAND = 0x9A
    OP_BOOLOR = 0x9B
    OP_NUMEQUAL = 0x9C
    OP_NUMEQUALVERIFY = 0x9D
    OP_NUMNOTEQUAL = 0x9E
    OP_LESSTHAN = 0x9F
    OP_GREATERTHAN = 0xA0
    OP_LESSTHANOREQUAL = 0xA1
    OP_GREATERTHANOREQUAL = 0xA2
    OP_MIN = 0xA3
    OP_MAX = 0xA4
    OP_WITHIN = 0xA5

    # Crypto
    OP_RIPEMD160 = 0xA6
    OP_SHA1 = 0xA7
    OP_SHA256 = 0xA8
    OP_HASH160 = 0xA9
    OP_HASH256 = 0xAA
    OP_CODESEPARATOR = 0xAB
    OP_CHECKSIG = 0xAC
    OP_CHECKSIGVERIFY = 0xAD
    OP_CHECKMULTISIG = 0xAE
    OP_CHECKMULTISIGVERIFY = 0xAF
    OP_CHECKSIGADD = 0xBA

    # Locktime
    OP_CHECKLOCKTIMEVERIFY = 0xB1
    OP_CHECKSEQUENCEVERIFY = 0xB2

    # Nop
    OP_NOP1 = 0xB0
    OP_NOP4 = 0xB3
    OP_NOP5 = 0xB4
    OP_NOP6 = 0xB5
    OP_NOP7 = 0xB6
    OP_NOP8 = 0xB7
    OP_NOP9 = 0xB8
    OP_NOP10 = 0xB9

    def serialize(self) -> bytes:
        """Serialize the transaction opcode."""
        return bytes([self])


def serialize_command_bytes(data: bytes):
    ret, length = bytearray(), len(data)
    if length < TransactionOpCode.OP_PUSHDATA1:
        ret += varint(length).serialize()
    elif length < (1 << 8):
        ret += TransactionOpCode.OP_PUSHDATA1.serialize() + bytes([length])
    elif length < (1 << 16):
        ret += TransactionOpCode.OP_PUSHDATA2.serialize() + length.to_bytes(2, "little")
    elif length < (1 << 32):
        ret += TransactionOpCode.OP_PUSHDATA4.serialize() + length.to_bytes(4, "little")
    else:  # pragma: no cover
        raise ValueError("Data is too long")
    ret += data
    return bytes(ret)


@dataclass(frozen=True)
class TransactionScript:
    """Bitcoin transaction script.

    Reference: https://en.bitcoin.it/wiki/Script

    """

    commands: tuple[TransactionOpCode | bytes, ...]

    def serialize(self):
        """Serialize the transaction script."""
        ret = bytearray()
        for command in self.commands:
            match command:
                case TransactionOpCode(code):
                    ret += code.serialize()
                case bytes(data):  # pragma: no branch
                    ret += serialize_command_bytes(data)
        return varint(len(ret)).serialize() + bytes(ret)

    @classmethod
    def deserialize(cls, data: IO[bytes]):
        """Deserialize a sequence of bytes into a transaction script."""
        script_length = varint.deserialize(data)
        reader = BytesIO(data.read(script_length))
        commands: list[TransactionOpCode | bytes] = []
        while reader.tell() < script_length:
            opcode, *_ = reader.read(1)
            match opcode:
                case TransactionOpCode.OP_PUSHDATA1:
                    length = int.from_bytes(reader.read(1), "little")
                    commands.append(reader.read(length))
                case TransactionOpCode.OP_PUSHDATA2:
                    length = int.from_bytes(reader.read(2), "little")
                    commands.append(reader.read(length))
                case TransactionOpCode.OP_PUSHDATA4:
                    length = int.from_bytes(reader.read(4), "little")
                    commands.append(reader.read(length))
                case length if length < TransactionOpCode.OP_PUSHDATA1:
                    commands.append(reader.read(length))
                case code if code in TransactionOpCode:
                    commands.append(TransactionOpCode(code))
                case _:
                    raise ValueError(f"Invalid opcode: {opcode}")
        return cls(tuple(commands))

    def __add__(self, other: Self) -> Self:
        return self.__class__(self.commands + other.commands)


@dataclass(frozen=True)
class TransactionInput:
    previous_transaction: bytes
    """Previous transaction SHA256 hash"""
    previous_index: int
    """UTXO index in the previous transaction"""
    script_signature: TransactionScript
    """Unlocking script"""
    sequence: int = 0xFFFFFFFF

    def serialize(self) -> bytes:
        return (
            self.previous_transaction
            + self.previous_index.to_bytes(4, "little")
            + self.script_signature.serialize()
            + self.sequence.to_bytes(4, "little")
        )

    @classmethod
    def deserialize(cls, data: IO[bytes]):
        previous_transaction = data.read(32)
        previous_index = int.from_bytes(data.read(4), "little")
        script_signature = TransactionScript.deserialize(data)
        sequence = int.from_bytes(data.read(4), "little")
        return cls(previous_transaction, previous_index, script_signature, sequence)


@dataclass(frozen=True)
class TransactionOutput:
    value: int
    """Value in satoshis (1 BTC = 100_000_000 satoshis)"""
    script_pubkey: TransactionScript
    """Locking script"""

    def serialize(self) -> bytes:
        return self.value.to_bytes(8, "little") + self.script_pubkey.serialize()

    @classmethod
    def deserialize(cls, data: IO[bytes]):
        value = int.from_bytes(data.read(8), "little")
        script_pubkey = TransactionScript.deserialize(data)
        return cls(value, script_pubkey)


@dataclass(frozen=True)
class Transaction:
    version: int
    inputs: tuple[TransactionInput, ...]
    outputs: tuple[TransactionOutput, ...]
    locktime: int
    """Block height or timestamp at which this transaction is valid"""
    hash: bytes | None = None
    """Transaction SHA256 hash"""

    def serialize(self) -> bytes:
        return self.version.to_bytes(4, "little") + (
            varint(len(self.inputs)).serialize()
            + b"".join(input_.serialize() for input_ in self.inputs)
            + varint(len(self.outputs)).serialize()
            + b"".join(output.serialize() for output in self.outputs)
            + self.locktime.to_bytes(4, "little")
        )

    @classmethod
    def deserialize(cls, data: IO[bytes]):
        version = int.from_bytes(data.read(4), "little")
        inputs = tuple(
            TransactionInput.deserialize(data) for _ in range(varint.deserialize(data))
        )
        outputs = tuple(
            TransactionOutput.deserialize(data) for _ in range(varint.deserialize(data))
        )
        locktime = int.from_bytes(data.read(4), "little")
        return cls(version, inputs, outputs, locktime)
