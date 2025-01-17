import functools
from collections.abc import Callable, Sequence
from typing import Concatenate

from sqlalchemy.orm import Session
from sqlalchemy.sql import select

from coincidence.block.types import Block
from coincidence.transaction.types.transaction import (
    Transaction,
    TransactionInput,
    TransactionOutput,
)

from . import schema


def wrap_transaction[**P, R](
    func: Callable[Concatenate[Session, P], R],
) -> Callable[Concatenate[Session, P], R]:
    @functools.wraps(func)
    def wrapped(session: Session, *args: P.args, **kwargs: P.kwargs) -> R:
        with session.begin_nested():
            return func(session, *args, **kwargs)

    return wrapped


@wrap_transaction
def insert_block(session: Session, height: int, block: Block):
    block_obj = schema.Blocks(
        id=block.hash,
        merkle_root=block.merkle_root,
        height=height,
        version=block.version,
        timestamp=block.timestamp,
        bits=block.bits,
        nonce=block.nonce,
        previous_id=block.previous_block[::-1] if height > 0 else None,
    )
    session.add(block_obj)
    return block_obj


@wrap_transaction
def insert_transactions(
    session: Session, block_id: bytes, transactions: Sequence[Transaction]
):
    duplicated = set(
        session.scalars(
            select(schema.Transactions.id).filter(
                schema.Transactions.id.in_(t.id for t in transactions)
            )
        )
    )
    txs: list[schema.Transactions] = []
    for transaction in transactions:
        if transaction.id in duplicated:
            continue
        transaction_obj = schema.Transactions(
            id=transaction.id,
            block_id=block_id,
            version=transaction.version,
            locktime=transaction.locktime,
        )
        txs.append(transaction_obj)
    session.bulk_save_objects(txs)
    txs_io: dict[
        bytes, tuple[list[schema.TransactionInputs], list[schema.TransactionOutputs]]
    ] = {}
    for transaction in transactions:
        if transaction.id in duplicated:
            continue
        txi = insert_transaction_inputs(session, transaction, transaction.inputs)
        txo = insert_transaction_outputs(session, transaction, transaction.outputs)
        txs_io[transaction.id] = (txi, txo)
    return [(tx, txs_io.get(tx.id)) for tx in txs]


@wrap_transaction
def insert_transaction_inputs(
    session: Session, transaction: Transaction, inputs: Sequence[TransactionInput]
):
    tx_inputs: list[schema.TransactionInputs] = []
    for index, tx_input in enumerate(inputs):
        transaction_input = schema.TransactionInputs(
            id=transaction.id,
            index=index,
            script_sig=(
                tx_input.script_signature.bytecode
                if tx_input.script_signature
                else None
            ),
            sequence=tx_input.sequence,
            previous=None,
        )
        if not transaction.is_coinbase:
            transaction_input.previous_transaction = tx_input.previous_transaction[::-1]
            transaction_input.previous_index = tx_input.previous_index
        tx_inputs.append(transaction_input)
    session.bulk_save_objects(tx_inputs)
    return tx_inputs


@wrap_transaction
def insert_transaction_outputs(
    session: Session, transaction: Transaction, outputs: Sequence[TransactionOutput]
):
    tx_outputs: list[schema.TransactionOutputs] = []
    for index, tx_output in enumerate(outputs):
        transaction_output = schema.TransactionOutputs(
            id=transaction.id,
            index=index,
            value=tx_output.value,
            script_pubkey=tx_output.script_pubkey.bytecode,
        )
        tx_outputs.append(transaction_output)
    session.bulk_save_objects(tx_outputs)
    return tx_outputs
