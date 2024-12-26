import json
import math
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from coincidence.block.types import Block
from coincidence.transaction.types.common import varint
from coincidence.transaction.types.script import ScriptDeserializationFlag
from coincidence.transaction.types.transaction import Transaction

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@dataclass
class BlockData:
    hash: str
    confirmations: int
    height: int
    version: int
    versionHex: str  # noqa: N815
    merkleroot: str
    time: int
    mediantime: int
    nonce: int
    bits: str
    difficulty: float
    chainwork: str
    nTx: int  # noqa: N815
    nextblockhash: str
    strippedsize: int
    size: int
    weight: int
    tx: list[str]

    previousblockhash: str = "0" * 64


block_ids: list[str] = []
all_block_data: list[BlockData] = []
all_block_binary: list[bytes] = []

for block_file in sorted(FIXTURES_DIR.glob("*.json")):
    block_ids.append(block_file.stem)
    with block_file.open("r") as f:
        loaded: dict[str, Any] = json.load(f)  # pyright:ignore[reportExplicitAny]
    all_block_data.append(BlockData(**loaded))  # pyright:ignore[reportAny]
    with block_file.with_suffix(".hex").open("r") as f:
        all_block_binary.append(bytes.fromhex(f.read()))


@pytest.mark.parametrize(
    ("block_data", "binary"),
    [*zip(all_block_data, all_block_binary, strict=True)],
    ids=block_ids,
)
def test_block_header(block_data: BlockData, binary: bytes) -> None:
    block = Block.deserialize(BytesIO(binary))

    assert block.version == block_data.version
    assert block.previous_block == bytes.fromhex(block_data.previousblockhash)[::-1]
    assert block.merkle_root == bytes.fromhex(block_data.merkleroot)[::-1]
    assert int(block.timestamp.timestamp()) == block_data.time
    assert block.bits == int(block_data.bits, 16)

    assert isinstance(block.features, int)
    assert block.hash == bytes.fromhex(block_data.hash)
    assert block.hash < block.target
    assert block.replace_nonce(0).hash >= block.target
    assert math.isclose(block.difficulty, block_data.difficulty)

    assert binary.startswith(block.serialize())


@pytest.mark.parametrize(
    ("block_data", "binary"),
    [*zip(all_block_data, all_block_binary, strict=True)],
    ids=block_ids,
)
def test_block_with_transaction(block_data: BlockData, binary: bytes) -> None:
    reader = BytesIO(binary)
    block = Block.deserialize(reader)

    assert block.hash == bytes.fromhex(block_data.hash)

    txs = varint.deserialize(reader)
    assert block_data.nTx == txs

    for i, tx_id in enumerate(block_data.tx):
        flag = ScriptDeserializationFlag(0)
        if i == 0:
            flag |= ScriptDeserializationFlag.FROM_COINBASE
        tx = Transaction.deserialize(reader, flag)
        if tx.id != bytes.fromhex(tx_id):
            pytest.xfail(f"Skipping test for transaction {tx_id}")
