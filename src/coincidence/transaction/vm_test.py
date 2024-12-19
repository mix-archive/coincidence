import pytest

from coincidence.transaction.types import TransactionOpCode, TransactionScript
from coincidence.transaction.vm import (
    InsufficientStackError,
    OpCodeRejectedError,
    decode_num,
    encode_num,
    evaluate_script,
)


@pytest.mark.parametrize(
    ("num", "expected"),
    [
        (0x00, b""),
        (0x01, b"\x01"),
        (0x7F, b"\x7f"),
        (-0x7F, b"\xff"),
        (0x80, b"\x80\x00"),
        (-0x80, b"\x80\x80"),
        (0xFF, b"\xff\x00"),
        (-0xFF, b"\xff\x80"),
        (0x100, b"\x00\x01"),
        (-0x100, b"\x00\x81"),
        (0x7FFF, b"\xff\x7f"),
        (-0x7FFF, b"\xff\xff"),
        (0x8000, b"\x00\x80\x00"),
        (-0x8000, b"\x00\x80\x80"),
    ],
    ids=(
        lambda x: repr(hex(x))  # pyright:ignore[reportAny]
        if isinstance(x, int)
        else repr(x.hex())
        if isinstance(x, bytes)
        else x
    ),
)
def test_encode_num(num: int, expected: bytes):
    assert encode_num(num) == expected
    assert decode_num(expected) == num


def test_op_if():
    # Test basic OP_IF with true condition
    script = TransactionScript(
        commands=(
            encode_num(1),  # True condition
            TransactionOpCode.OP_IF,
            encode_num(42),
            TransactionOpCode.OP_ENDIF,
        )
    )
    _, stack = evaluate_script(script, b"")
    assert decode_num(stack.pop()) == 42

    # Test basic OP_IF with false condition
    script = TransactionScript(
        commands=(
            encode_num(0),  # False condition
            TransactionOpCode.OP_IF,
            encode_num(42),
            TransactionOpCode.OP_ENDIF,
        )
    )
    _, stack = evaluate_script(script, b"")
    assert len(stack) == 0

    # Test OP_IF with ELSE
    script = TransactionScript(
        commands=(
            encode_num(0),  # False condition
            TransactionOpCode.OP_IF,
            encode_num(42),
            TransactionOpCode.OP_ELSE,
            encode_num(43),
            TransactionOpCode.OP_ENDIF,
        )
    )
    _, stack = evaluate_script(script, b"")
    assert decode_num(stack.pop()) == 43

    # Test OP_NOTIF
    script = TransactionScript(
        commands=(
            encode_num(0),  # False condition
            TransactionOpCode.OP_NOTIF,
            encode_num(42),
            TransactionOpCode.OP_ENDIF,
        )
    )
    _, stack = evaluate_script(script, b"")
    assert decode_num(stack.pop()) == 42

    # Test nested IF statements
    script = TransactionScript(
        commands=(
            encode_num(1),  # True condition for outer IF
            TransactionOpCode.OP_IF,
            encode_num(1),  # True condition for inner IF
            TransactionOpCode.OP_IF,
            encode_num(42),
            TransactionOpCode.OP_ENDIF,
            TransactionOpCode.OP_ENDIF,
        )
    )
    _, stack = evaluate_script(script, b"")
    assert decode_num(stack.pop()) == 42

    # Test unmatched IF
    script = TransactionScript(
        commands=(
            encode_num(1),
            TransactionOpCode.OP_IF,
            encode_num(42),
        )
    )
    with pytest.raises(ValueError, match="Unmatched OP_IF"):
        _ = evaluate_script(script, b"")

    # Test insufficient stack
    script = TransactionScript(
        commands=(
            TransactionOpCode.OP_IF,
            encode_num(42),
            TransactionOpCode.OP_ENDIF,
        )
    )
    with pytest.raises(InsufficientStackError):
        _ = evaluate_script(script, b"")


def test_op_hash160():
    empty_script = TransactionScript(
        commands=(TransactionOpCode.OP_NOP, TransactionOpCode.OP_HASH160)
    )
    with pytest.raises(InsufficientStackError, match="op_hash"):
        exec_count, stack = evaluate_script(empty_script, b"")

    script = TransactionScript(commands=(b"hello world", TransactionOpCode.OP_HASH160))
    exec_count, stack = evaluate_script(script, b"")
    assert exec_count == 1
    assert [*stack] == [bytes.fromhex("d7d5ee7824ff93f94c3055af9382c86c68b5ca92")]


def test_op_checksig():
    z = bytes.fromhex(
        "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d"
    )
    sec = bytes.fromhex(
        "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
    )
    sig = bytes.fromhex(
        "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601"
    )
    script = TransactionScript(commands=(sig, sec, TransactionOpCode.OP_CHECKSIGVERIFY))
    exec_count, stack = evaluate_script(script, z)
    assert exec_count == 1
    assert len(stack) == 0

    mutated_z = z[:-1] + bytes([z[-1] + 1])

    with pytest.raises(OpCodeRejectedError, match="Verify"):
        exec_count, stack = evaluate_script(script, mutated_z)


@pytest.mark.parametrize(
    ("op", "args", "expected"),
    [
        (TransactionOpCode.OP_1ADD, [1], 2),
        (TransactionOpCode.OP_1SUB, [1], 0),
        (TransactionOpCode.OP_NEGATE, [42], -42),
        (TransactionOpCode.OP_ABS, [-42], 42),
        (TransactionOpCode.OP_NOT, [0], 1),
        (TransactionOpCode.OP_NOT, [1], 0),
        (TransactionOpCode.OP_0NOTEQUAL, [0], 0),
        (TransactionOpCode.OP_0NOTEQUAL, [1], 1),
        (TransactionOpCode.OP_ADD, [2, 3], 5),
        (TransactionOpCode.OP_SUB, [5, 3], 2),
        (TransactionOpCode.OP_BOOLAND, [1, 1], 1),
        (TransactionOpCode.OP_BOOLAND, [0, 1], 0),
        (TransactionOpCode.OP_BOOLOR, [0, 0], 0),
        (TransactionOpCode.OP_BOOLOR, [0, 1], 1),
        (TransactionOpCode.OP_NUMEQUAL, [5, 5], 1),
        (TransactionOpCode.OP_NUMEQUAL, [4, 5], 0),
        (TransactionOpCode.OP_NUMEQUALVERIFY, [5, 5], True),
        (TransactionOpCode.OP_NUMEQUALVERIFY, [4, 5], False),
        (TransactionOpCode.OP_NUMNOTEQUAL, [4, 5], 1),
        (TransactionOpCode.OP_NUMNOTEQUAL, [5, 5], 0),
        (TransactionOpCode.OP_LESSTHAN, [4, 5], 1),
        (TransactionOpCode.OP_LESSTHAN, [5, 5], 0),
        (TransactionOpCode.OP_GREATERTHAN, [6, 5], 1),
        (TransactionOpCode.OP_GREATERTHAN, [5, 5], 0),
        (TransactionOpCode.OP_LESSTHANOREQUAL, [5, 5], 1),
        (TransactionOpCode.OP_LESSTHANOREQUAL, [6, 5], 0),
        (TransactionOpCode.OP_GREATERTHANOREQUAL, [5, 5], 1),
        (TransactionOpCode.OP_GREATERTHANOREQUAL, [4, 5], 0),
        (TransactionOpCode.OP_MIN, [4, 5], 4),
        (TransactionOpCode.OP_MAX, [4, 5], 5),
        (TransactionOpCode.OP_WITHIN, [4, 3, 5], 1),
        (TransactionOpCode.OP_WITHIN, [3, 3, 5], 1),
        (TransactionOpCode.OP_WITHIN, [5, 3, 5], 0),
    ],
    ids=lambda x: x.name if isinstance(x, TransactionOpCode) else str(x),  # pyright:ignore[reportAny]
)
def test_arithmetic(op: TransactionOpCode, args: list[int], expected: int | bool):
    if all(0 <= arg <= 16 for arg in args):
        # Test with OP_1, OP_2, ..., OP_16
        commands = [
            (
                TransactionOpCode(TransactionOpCode.OP_1 + arg - 1)
                if arg
                else TransactionOpCode.OP_0
            )
            for arg in args
        ]
    else:
        commands = [*map(encode_num, args)]
    script = TransactionScript(commands=(*commands, op))
    if expected is False:
        with pytest.raises(OpCodeRejectedError):
            _ = evaluate_script(script, b"")
        return
    _, stack = evaluate_script(script, b"")
    assert [*map(decode_num, stack)] == ([] if expected is True else [expected])


def test_op_return():
    script = TransactionScript(commands=(b"hello world", TransactionOpCode.OP_RETURN))
    with pytest.raises(OpCodeRejectedError, match="OP_RETURN"):
        _ = evaluate_script(script, b"")


def test_op_altstack():
    # Test OP_TOALTSTACK
    script = TransactionScript(
        commands=(encode_num(42), TransactionOpCode.OP_TOALTSTACK)
    )
    _, stack = evaluate_script(script, b"")
    assert len(stack) == 0  # Main stack should be empty

    # Test OP_FROMALTSTACK
    script = TransactionScript(
        commands=(
            encode_num(42),
            TransactionOpCode.OP_TOALTSTACK,
            TransactionOpCode.OP_FROMALTSTACK,
        )
    )
    _, stack = evaluate_script(script, b"")
    assert decode_num(stack.pop()) == 42

    # Test OP_FROMALTSTACK with empty alt stack
    script = TransactionScript(commands=(TransactionOpCode.OP_FROMALTSTACK,))
    with pytest.raises(InsufficientStackError):
        _ = evaluate_script(script, b"")

    # Test OP_TOALTSTACK with insufficient stack
    script = TransactionScript(commands=(TransactionOpCode.OP_TOALTSTACK,))
    with pytest.raises(InsufficientStackError):
        _ = evaluate_script(script, b"")


@pytest.mark.parametrize(
    ("op", "input_stack", "expected"),
    [
        (TransactionOpCode.OP_DROP, [42], []),
        (TransactionOpCode.OP_DROP, [], None),
        (TransactionOpCode.OP_2DROP, [42, 43], []),
        (TransactionOpCode.OP_2DROP, [42], None),
        (TransactionOpCode.OP_DUP, [42], [42, 42]),
        (TransactionOpCode.OP_DUP, [], None),
        (TransactionOpCode.OP_2DUP, [42, 43], [42, 43, 42, 43]),
        (TransactionOpCode.OP_2DUP, [42], None),
        (TransactionOpCode.OP_3DUP, [42, 43, 44], [42, 43, 44, 42, 43, 44]),
        (TransactionOpCode.OP_3DUP, [42, 43], None),
        (TransactionOpCode.OP_OVER, [42, 43], [42, 43, 42]),
        (TransactionOpCode.OP_2OVER, [42, 43, 44, 45], [42, 43, 44, 45, 42, 43]),
        (TransactionOpCode.OP_ROT, [42, 43, 44], [43, 44, 42]),
        (TransactionOpCode.OP_ROT, [42, 43], None),
        (TransactionOpCode.OP_2ROT, [42, 43, 44, 45, 46, 47], [44, 45, 46, 47, 42, 43]),
        (TransactionOpCode.OP_2ROT, [42, 43, 44], None),
        (TransactionOpCode.OP_SWAP, [42, 43], [43, 42]),
        (TransactionOpCode.OP_SWAP, [42], None),
        (TransactionOpCode.OP_2SWAP, [42, 43, 44, 45], [44, 45, 42, 43]),
        (TransactionOpCode.OP_2SWAP, [42, 43, 44], None),
        (TransactionOpCode.OP_IFDUP, [0], [0]),
        (TransactionOpCode.OP_IFDUP, [42], [42, 42]),
        (TransactionOpCode.OP_IFDUP, [], None),
        (TransactionOpCode.OP_NIP, [42, 43], [42]),
        (TransactionOpCode.OP_NIP, [42], None),
        (TransactionOpCode.OP_PICK, [3, 2, 1, 0], [3, 2, 1, 1]),
        (TransactionOpCode.OP_PICK, [3, 2, 1], [3, 2, 3]),
        (TransactionOpCode.OP_PICK, [3, 2], None),
        (TransactionOpCode.OP_ROLL, [0, 1, 2, 2], [0, 2, 1]),
        (TransactionOpCode.OP_ROLL, [3, 2, 1, 0], [3, 2, 1]),
        (TransactionOpCode.OP_ROLL, [3, 2, 1], [3, 2]),
        (TransactionOpCode.OP_ROLL, [3, 2], None),
        (TransactionOpCode.OP_TUCK, [42, 43], [43, 42, 43]),
        (TransactionOpCode.OP_TUCK, [42], None),
        (TransactionOpCode.OP_SIZE, [0x7FFF], [0x7FFF, 2]),
        (TransactionOpCode.OP_SIZE, [-0xFFFF], [-0xFFFF, 3]),
        (TransactionOpCode.OP_SIZE, [], None),
        (TransactionOpCode.OP_DEPTH, [42, 43], [42, 43, 2]),
        (TransactionOpCode.OP_DEPTH, [], [0]),
    ],
    ids=lambda x: x.name if isinstance(x, TransactionOpCode) else str(x),  # pyright:ignore[reportAny]
)
def test_stack_ops(
    op: TransactionOpCode, input_stack: list[int], expected: list[int] | None
):
    script = TransactionScript(commands=(*map(encode_num, input_stack), op))
    if expected is None:
        with pytest.raises(InsufficientStackError):
            _ = evaluate_script(script, b"")
        return
    _, stack = evaluate_script(script, b"")
    assert [*map(decode_num, stack)] == expected