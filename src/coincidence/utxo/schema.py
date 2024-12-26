from datetime import datetime
from typing import Any, final, override

from sqlalchemy import (
    DateTime,
    Dialect,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    TypeDecorator,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


@final
class Hash256(TypeDecorator[bytes]):
    impl = String(64)
    cache_ok = True

    @override
    def process_bind_param(self, value: bytes | None, dialect: Dialect):
        return value.hex() if value is not None else None

    @override
    def process_result_value(self, value: Any, dialect: Dialect) -> bytes | None:  # pyright:ignore[reportExplicitAny,reportAny]
        return bytes.fromhex(value) if isinstance(value, str) else None


class Base(DeclarativeBase):
    pass


class Blocks(Base):
    __tablename__: str = "blocks"

    id: Mapped[bytes] = mapped_column(Hash256, primary_key=True)
    merkle_root: Mapped[bytes] = mapped_column(
        Hash256, nullable=False, index=True, unique=True
    )
    height: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    bits: Mapped[int] = mapped_column(Integer, nullable=False)
    nonce: Mapped[int] = mapped_column(Integer, nullable=False)

    previous_id: Mapped[bytes | None] = mapped_column(
        Hash256,
        ForeignKey("blocks.id"),
        nullable=True,
        index=True,
        default=None,
    )
    previous: Mapped["Blocks | None"] = relationship(
        back_populates="next", remote_side=[id]
    )
    next: Mapped["Blocks | None"] = relationship(back_populates="previous")

    transactions: Mapped[list["Transactions"]] = relationship(back_populates="block")


class Transactions(Base):
    __tablename__: str = "transactions"

    id: Mapped[bytes] = mapped_column(Hash256, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    locktime: Mapped[int] = mapped_column(Integer, nullable=False)

    block_id: Mapped[bytes] = mapped_column(
        Hash256, ForeignKey("blocks.id"), nullable=False, index=True
    )
    block: Mapped["Blocks"] = relationship(back_populates="transactions")

    inputs: Mapped[list["TransactionInputs"]] = relationship(
        back_populates="transaction"
    )
    outputs: Mapped[list["TransactionOutputs"]] = relationship(
        back_populates="transaction"
    )


class TransactionOutputs(Base):
    __tablename__: str = "transaction_outputs"

    id: Mapped[bytes] = mapped_column(
        Hash256, ForeignKey("transactions.id"), primary_key=True, index=True
    )
    index: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[int] = mapped_column(Integer, nullable=False)
    script_pubkey: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    spent_by: Mapped["TransactionInputs | None"] = relationship(
        back_populates="previous"
    )

    transaction: Mapped["Transactions"] = relationship(back_populates="outputs")


class TransactionInputs(Base):
    __tablename__: str = "transaction_inputs"

    id: Mapped[bytes] = mapped_column(
        Hash256, ForeignKey("transactions.id"), primary_key=True, index=True
    )
    index: Mapped[int] = mapped_column(Integer, primary_key=True)
    script_sig: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True, default=None
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)

    previous_transaction: Mapped[bytes | None] = mapped_column(
        Hash256, nullable=True, index=True
    )
    previous_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    previous: Mapped["TransactionOutputs | None"] = relationship(
        foreign_keys=[previous_transaction, previous_index],
        back_populates="spent_by",
    )

    transaction: Mapped["Transactions"] = relationship(back_populates="inputs")

    __table_args__ = (  # pyright:ignore[reportAny,reportUnannotatedClassAttribute]
        ForeignKeyConstraint(
            [previous_transaction, previous_index],
            [TransactionOutputs.id, TransactionOutputs.index],
        ),
        Index(None, previous_index, previous_transaction, unique=True),
    )
