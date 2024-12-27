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
    PrimaryKeyConstraint,
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
    def process_result_value(
        self,
        value: Any,  # pyright:ignore[reportExplicitAny,reportAny]
        dialect: Dialect,
    ) -> bytes | None:
        return bytes.fromhex(value) if isinstance(value, str) else None


class Base(DeclarativeBase):
    pass


@final
class Blocks(Base):
    __tablename__: str = "blocks"

    id: Mapped[bytes] = mapped_column(Hash256, primary_key=True)
    merkle_root: Mapped[bytes] = mapped_column(
        Hash256, nullable=False, index=True, unique=True
    )
    height: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    bits: Mapped[int] = mapped_column(Integer, nullable=False)
    nonce: Mapped[int] = mapped_column(Integer, nullable=False)

    previous_id: Mapped[bytes | None] = mapped_column(
        Hash256,
        ForeignKey("blocks.id"),
        nullable=True,
        index=True,
    )
    previous: Mapped["Blocks | None"] = relationship(
        back_populates="next", remote_side=[id]
    )
    next: Mapped["Blocks | None"] = relationship(
        back_populates="previous",
    )

    transactions: Mapped[list["Transactions"]] = relationship(back_populates="block")


@final
class Transactions(Base):
    __tablename__: str = "transactions"

    id: Mapped[bytes] = mapped_column(Hash256, index=True, primary_key=True)
    block_id: Mapped[bytes] = mapped_column(
        Hash256, ForeignKey(Blocks.id), index=True, nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    locktime: Mapped[int] = mapped_column(Integer, nullable=False)

    block: Mapped["Blocks"] = relationship(back_populates="transactions")

    inputs: Mapped[list["TransactionInputs"]] = relationship(
        back_populates="transaction"
    )
    outputs: Mapped[list["TransactionOutputs"]] = relationship(
        back_populates="transaction"
    )


@final
class TransactionOutputs(Base):
    __tablename__: str = "transaction_outputs"

    id: Mapped[bytes] = mapped_column(
        Hash256, ForeignKey(Transactions.id), index=True, nullable=False
    )
    index: Mapped[int] = mapped_column(Integer, nullable=False)
    value: Mapped[int] = mapped_column(Integer, nullable=False)
    script_pubkey: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    spent_by: Mapped["TransactionInputs | None"] = relationship(
        back_populates="previous"
    )

    transaction: Mapped["Transactions"] = relationship(back_populates="outputs")

    __table_args__ = (  # pyright:ignore[reportAny]
        PrimaryKeyConstraint(id, index),
    )


@final
class TransactionInputs(Base):
    __tablename__: str = "transaction_inputs"

    id: Mapped[bytes] = mapped_column(
        Hash256, ForeignKey(Transactions.id), index=True, nullable=False
    )
    index: Mapped[int] = mapped_column(Integer, nullable=False)
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

    __table_args__ = (  # pyright:ignore[reportAny]
        PrimaryKeyConstraint(id, index),
        ForeignKeyConstraint(
            [previous_transaction, previous_index],
            [TransactionOutputs.id, TransactionOutputs.index],
        ),
        Index(None, previous_index, previous_transaction, unique=True),
    )
