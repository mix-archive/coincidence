import abc
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Flag, auto
from typing import IO, Self, final, override

from base58 import b58decode_check

from coincidence.crypto.keypair import BitcoinPublicKey
from coincidence.crypto.utils import RIPEMD160

from .common import decode_num, encode_num, varint
from .opcode import (
    Command,
    InvalidOpcodeError,
    TransactionOpCode,
    build_script_bytecode,
    dissect_script_bytecode,
    read_script_bytecode,
)


class ScriptDeserializationFlag(Flag):
    FROM_COINBASE = auto()
    FROM_INPUT = auto()
    FROM_OUTPUT = auto()

    SEGREGATED_WITNESS = auto()
    TAPROOT = auto()


class BaseTransactionScript(abc.ABC):
    @property
    @abc.abstractmethod
    def bytecode(self) -> bytes:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        raise NotImplementedError

    @classmethod
    def deserialize(
        cls, reader: IO[bytes], flags: ScriptDeserializationFlag
    ) -> "BaseTransactionScript":
        bytecode = read_script_bytecode(reader)
        for dispatch in cls.__subclasses__():
            if dispatch is CommonTransactionScript:
                continue
            if script := dispatch.from_bytecode(bytecode, flags):
                return script
        return CommonTransactionScript(bytecode)

    def serialize(self) -> bytes:
        bytecode = self.bytecode
        return varint(len(bytecode)).serialize() + bytecode

    @property
    def commands(self) -> tuple[Command, ...]:
        return dissect_script_bytecode(self.bytecode)

    @override
    def __repr__(self):
        try:
            commands = repr([*self.commands])
        except InvalidOpcodeError:
            commands = "..."
        bytecode = repr(self.bytecode)
        if len(bytecode) > 32:  # noqa: PLR2004
            bytecode = bytecode[:16] + " [...] " + bytecode[-16:]
        return f"{self.__class__.__name__}({commands=:s}, {bytecode=:s})"

    def __add__(self, other: Self):
        return CommonTransactionScript(self.bytecode + other.bytecode)


@final
@dataclass(frozen=True, repr=False)
class CommonTransactionScript(BaseTransactionScript):
    _bytecode: bytes = b""

    @property
    @override
    def bytecode(self) -> bytes:
        return self._bytecode

    @classmethod
    @override
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        return cls(bytecode)

    @classmethod
    def from_commands(cls, commands: Iterable[Command]) -> Self:
        return cls(build_script_bytecode(commands))


@final
@dataclass(frozen=True, repr=False)
class CoinbaseScript(BaseTransactionScript):
    height: int | None = None
    remains: bytes = b""

    @property
    @override
    def bytecode(self) -> bytes:
        return (
            build_script_bytecode([encode_num(self.height)]) if self.height else b""
        ) + self.remains

    @classmethod
    @override
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        if not (
            flags & ScriptDeserializationFlag.FROM_COINBASE
            and flags & ScriptDeserializationFlag.FROM_INPUT
        ):
            return None
        # Because coinbase scripts includes very random script, we can't really
        # serialize it back to the original script. So we just parse first bytes
        matched = re.match(
            rb"^(\x01.{1}|\x02.{2}|\x03.{3}|\x04.{4})(.*)$",
            bytecode,
            re.DOTALL,
        )
        if matched is None:
            return cls(remains=bytecode)
        height_byte, remains = matched.groups()
        return cls(decode_num(height_byte[1:]), remains)


@final
@dataclass(frozen=True, repr=False)
class PayToPublicKeyScript(BaseTransactionScript):
    pubkey: BitcoinPublicKey

    @property
    @override
    def bytecode(self) -> bytes:
        return build_script_bytecode([self.pubkey.sec, TransactionOpCode.OP_CHECKSIG])

    @classmethod
    @override
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        if not flags & ScriptDeserializationFlag.FROM_OUTPUT:
            return None
        commands = dissect_script_bytecode(bytecode)
        match commands:
            case (bytes(pubkey), TransactionOpCode.OP_CHECKSIG) if (
                len(pubkey) in (32 + 1, 64 + 1)
            ):
                pk = BitcoinPublicKey.from_sec(pubkey)
                return cls(pk)
            case _:
                return None


@final
@dataclass(frozen=True, repr=False)
class PayToPublicKeyHashScript(BaseTransactionScript):
    hash160: bytes

    @property
    @override
    def bytecode(self) -> bytes:
        return build_script_bytecode(
            [
                TransactionOpCode.OP_DUP,
                TransactionOpCode.OP_HASH160,
                self.hash160,
                TransactionOpCode.OP_EQUALVERIFY,
                TransactionOpCode.OP_CHECKSIG,
            ]
        )

    @classmethod
    @override
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        if not flags & ScriptDeserializationFlag.FROM_OUTPUT:
            return None
        commands = dissect_script_bytecode(bytecode)
        match commands:
            case (
                TransactionOpCode.OP_DUP,
                TransactionOpCode.OP_HASH160,
                bytes(hash160),
                TransactionOpCode.OP_EQUALVERIFY,
                TransactionOpCode.OP_CHECKSIG,
            ) if len(hash160) == RIPEMD160().digest_size:
                return cls(hash160)
            case _:
                return None

    @classmethod
    def from_address(cls, address: str) -> Self:
        return cls(b58decode_check(address)[1:])


@final
@dataclass(frozen=True, repr=False)
class SignatureScript(BaseTransactionScript):
    signature: bytes
    pubkey: BitcoinPublicKey

    @property
    @override
    def bytecode(self) -> bytes:
        return build_script_bytecode([self.signature, self.pubkey.sec])

    @classmethod
    @override
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        if not flags & ScriptDeserializationFlag.FROM_INPUT:
            return None
        commands = dissect_script_bytecode(bytecode)
        match commands:
            case (bytes(signature), bytes(pubkey)) if (
                len(signature) > 0 and len(pubkey) > 0
            ):
                pk = BitcoinPublicKey.from_sec(pubkey)
                return cls(signature, pk)
            case _:
                return None
