import dataclasses
from dataclasses import dataclass
from enum import IntEnum
from typing import IO, Self

from coincidence.crypto import sha256

from .common import varint
from .script import (
    BaseTransactionScript,
    CommonTransactionScript,
    ScriptDeserializationFlag,
)


class SignatureHashTypes(IntEnum):
    """Signature hash types for transaction signature verification.

    Ref: https://en.bitcoin.it/wiki/OP_CHECKSIG
    """

    ALL = 0x01
    NONE = 0x02
    SINGLE = 0x03
    ANYONECANPAY = 0x80


@dataclass(frozen=True)
class TransactionInput:
    previous_transaction: bytes
    """Previous transaction SHA256 hash"""
    previous_index: int
    """UTXO index in the previous transaction"""
    script_signature: BaseTransactionScript | None = None
    """Unlocking script"""
    sequence: int = 0xFFFFFFFF

    def serialize(self) -> bytes:
        script_signature = self.script_signature or CommonTransactionScript()
        return (
            self.previous_transaction
            + self.previous_index.to_bytes(4, "little")
            + script_signature.serialize()
            + self.sequence.to_bytes(4, "little")
        )

    @classmethod
    def deserialize(cls, data: IO[bytes], flags: ScriptDeserializationFlag):
        previous_transaction = data.read(32)
        previous_index = int.from_bytes(data.read(4), "little")
        if flags & flags.FROM_COINBASE and not (
            previous_transaction == bytes(32) and previous_index == 0xFFFFFFFF  # noqa: PLR2004
        ):
            flags &= ~ScriptDeserializationFlag.FROM_COINBASE
        flags |= ScriptDeserializationFlag.FROM_INPUT
        script_signature = BaseTransactionScript.deserialize(data, flags)
        sequence = int.from_bytes(data.read(4), "little")
        return cls(previous_transaction, previous_index, script_signature, sequence)


@dataclass(frozen=True)
class TransactionOutput:
    value: int
    """Value in satoshis (1 BTC = 100_000_000 satoshis)"""
    script_pubkey: BaseTransactionScript
    """Locking script"""

    def serialize(self) -> bytes:
        return self.value.to_bytes(8, "little") + self.script_pubkey.serialize()

    @classmethod
    def deserialize(cls, data: IO[bytes], flags: ScriptDeserializationFlag):
        value = int.from_bytes(data.read(8), "little")
        flags |= ScriptDeserializationFlag.FROM_OUTPUT
        script_pubkey = BaseTransactionScript.deserialize(data, flags)
        return cls(value, script_pubkey)


@dataclass(frozen=True)
class Transaction:
    version: int
    inputs: tuple[TransactionInput, ...]
    outputs: tuple[TransactionOutput, ...]
    locktime: int
    """Block height or timestamp at which this transaction is valid"""

    def serialize(self) -> bytes:
        return self.version.to_bytes(4, "little") + (
            varint(len(self.inputs)).serialize()
            + b"".join(input_.serialize() for input_ in self.inputs)
            + varint(len(self.outputs)).serialize()
            + b"".join(output.serialize() for output in self.outputs)
            + self.locktime.to_bytes(4, "little")
        )

    @classmethod
    def deserialize(cls, data: IO[bytes], flags: ScriptDeserializationFlag):
        version = int.from_bytes(data.read(4), "little")
        total_inputs = varint.deserialize(data)
        if flags & flags.FROM_COINBASE and total_inputs != 1:
            flags &= ~ScriptDeserializationFlag.FROM_COINBASE
        inputs = tuple(
            TransactionInput.deserialize(data, flags) for _ in range(total_inputs)
        )
        total_outputs = varint.deserialize(data)
        outputs = tuple(
            TransactionOutput.deserialize(data, flags) for _ in range(total_outputs)
        )
        locktime = int.from_bytes(data.read(4), "little")
        return cls(version, inputs, outputs, locktime)

    @property
    def id(self) -> bytes:
        """Transaction ID in reversed byte order."""
        return sha256(sha256(self.serialize()))[::-1]

    @property
    def is_coinbase(self) -> bool:
        """Check if the transaction is a coinbase transaction."""
        return (
            len(self.inputs) == 1
            and self.inputs[0].previous_transaction == bytes(32)
            and self.inputs[0].previous_index == 0xFFFFFFFF  # noqa: PLR2004
        )

    def signature_hash(
        self,
        input_index: int,
        prev_script_pubkey: BaseTransactionScript,
        hash_type: SignatureHashTypes = SignatureHashTypes.ALL,
    ) -> bytes:
        """Calculate the signature hash for the input.

        Args:
            input_index (int): Index of the input to sign.
            prev_script_pubkey (TransactionScript): Previous output locking script.
            hash_type (SignatureHashTypes): Signature hash type.

        Returns:
            bytes: The signature hash after double SHA256 hashing.

        """
        inputs = tuple(
            dataclasses.replace(
                tx_in,
                script_signature=(prev_script_pubkey if i == input_index else None),
            )
            for i, tx_in in enumerate(self.inputs)
        )
        hash_target = dataclasses.replace(self, inputs=inputs).serialize()
        hash_target += hash_type.to_bytes(4, "little")
        return sha256(sha256(hash_target))

    def replace_input_script(
        self, input_index: int, script: BaseTransactionScript
    ) -> Self:
        """Replace the script signature for the input at the given index.

        This method creates a new transaction object with the script signature, which
        unlocks the input at the given index.
        """
        inputs = tuple(
            dataclasses.replace(
                tx_in,
                script_signature=(
                    script if i == input_index else tx_in.script_signature
                ),
            )
            for i, tx_in in enumerate(self.inputs)
        )
        return dataclasses.replace(self, inputs=inputs)
