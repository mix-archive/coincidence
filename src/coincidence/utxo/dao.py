import functools
from collections.abc import Callable, Sequence
from typing import Concatenate

from sqlalchemy.orm import Session

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
            try:
                return func(session, *args, **kwargs)
            except Exception:
                session.rollback()
                raise

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
    session: Session, block: schema.Blocks, transactions: Sequence[Transaction]
):
    txs: list[schema.Transactions] = []
    for tx in transactions:
        transaction = schema.Transactions(
            id=tx.id,
            version=tx.version,
            locktime=tx.locktime,
            block=block,
        )
        session.add(transaction)
        txs.append(transaction)
    for tx in transactions:
        insert_transaction_inputs(session, tx, tx.inputs)
        insert_transaction_outputs(session, tx, tx.outputs)
    return txs


@wrap_transaction
def insert_transaction_inputs(
    session: Session, transaction: Transaction, inputs: Sequence[TransactionInput]
):
    for index, tx_input in enumerate(inputs):
        previous = None
        if not transaction.is_coinbase:
            previous = (
                session.query(schema.TransactionOutputs)
                .filter_by(
                    id=tx_input.previous_transaction[::-1],
                    index=tx_input.previous_index,
                )
                .one()
            )
        transaction_input = schema.TransactionInputs(
            id=transaction.id,
            index=index,
            script_sig=(
                tx_input.script_signature.bytecode
                if tx_input.script_signature
                else None
            ),
            sequence=tx_input.sequence,
            previous=previous,
        )
        session.add(transaction_input)


@wrap_transaction
def insert_transaction_outputs(
    session: Session, transaction: Transaction, outputs: Sequence[TransactionOutput]
):
    for index, tx_output in enumerate(outputs):
        transaction_output = schema.TransactionOutputs(
            id=transaction.id,
            index=index,
            value=tx_output.value,
            script_pubkey=tx_output.script_pubkey.bytecode,
        )
        session.add(transaction_output)
