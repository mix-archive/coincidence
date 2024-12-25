import functools
import inspect
from collections import deque
from collections.abc import Callable
from enum import IntFlag, auto
from typing import Any, Concatenate

from coincidence.crypto import ripemd160, sha1, sha256, verify_signature

from .types.opcode import Command, TransactionOpCode
from .types.script import BaseTransactionScript
from .types.transaction import SignatureHashTypes

type Commands = deque[Command]
type Stack = deque[bytes]
type OpCodeCallback = Callable[Concatenate[Stack, ...], None]


class OpCodeInstructArguments(IntFlag):
    stack = auto()
    alt_stack = auto()
    current_op = auto()
    cmds = auto()
    z = auto()


_TRANSACTION_OP_TABLE: dict[
    TransactionOpCode, tuple[OpCodeCallback, OpCodeInstructArguments]
] = {}


_IMMEDIATE_OP_TABLE: dict[TransactionOpCode, int] = {
    TransactionOpCode.OP_1NEGATE: -1,
    TransactionOpCode.OP_0: 0,
    TransactionOpCode.OP_1: 1,
    TransactionOpCode.OP_2: 2,
    TransactionOpCode.OP_3: 3,
    TransactionOpCode.OP_4: 4,
    TransactionOpCode.OP_5: 5,
    TransactionOpCode.OP_6: 6,
    TransactionOpCode.OP_7: 7,
    TransactionOpCode.OP_8: 8,
    TransactionOpCode.OP_9: 9,
    TransactionOpCode.OP_10: 10,
    TransactionOpCode.OP_11: 11,
    TransactionOpCode.OP_12: 12,
    TransactionOpCode.OP_13: 13,
    TransactionOpCode.OP_14: 14,
    TransactionOpCode.OP_15: 15,
    TransactionOpCode.OP_16: 16,
}


class OpCodeRejectedError(ValueError):
    pass


class InsufficientStackError(OpCodeRejectedError):
    pass


def encode_num(num: int | bool):
    """Encode an integer as a byte array.

    The stacks hold byte vectors. When used as numbers, byte vectors are interpreted as
    little-endian variable-length integers with the most significant bit determining the
    sign of the integer. Thus 0x81 represents -1. 0x80 is another representation of zero
    (so called negative 0). Positive 0 is represented by a null-length vector. Byte
    vectors are interpreted as Booleans where False is represented by any representation
    of zero and True is represented by any representation of non-zero.
    """
    if num == 0:
        return b""
    ret = bytearray()
    ret += (abs_num := abs(num)).to_bytes((abs_num.bit_length() + 7) // 8, "little")
    if ret[-1] & 0x80:
        ret.append(0x00 if num > 0 else 0x80)
    elif num < 0:
        ret[-1] |= 0x80
    return bytes(ret)


def decode_num(data: bytes):
    """Decode a byte array as an integer."""
    if not data:
        return 0
    negative = data[-1] & 0x80
    data = data[:-1] + bytes([last] if (last := data[-1] & 0x7F) else [])
    return int.from_bytes(data, "little") * (-1 if negative else 1)


def register_op(*ops: TransactionOpCode):
    def decorator[T: OpCodeCallback](func: T) -> T:
        signature = inspect.signature(func)
        flags = OpCodeInstructArguments.stack
        try:
            for arg in signature.parameters:
                flags |= OpCodeInstructArguments[arg]
        except KeyError as e:  # pragma: no cover
            raise ValueError(f"Invalid arguments: {signature}") from e
        for op in ops:
            if conflicted := _TRANSACTION_OP_TABLE.get(op):  # pragma: no cover
                raise ValueError(f"Conflicting opcode: {op=} {conflicted=} {func=}")
            _TRANSACTION_OP_TABLE[op] = (func, flags)
        return func

    return decorator


def assert_stack_size(size: int):
    def decorator[**P, R](
        func: Callable[Concatenate[Stack, P], R],
    ) -> Callable[Concatenate[Stack, P], R]:
        @functools.wraps(func)
        def wrapper(stack: Stack, *args: P.args, **kwargs: P.kwargs) -> R:
            if (actual := len(stack)) < size:
                raise InsufficientStackError(
                    f"{func=} requires {size=} elements, but {actual=} elements found"
                )
            return func(stack, *args, **kwargs)

        return wrapper

    return decorator


def op_nop(stack: Stack):  # pyright:ignore[reportUnusedParameter]
    pass


# batch register NOP opcodes
for op in TransactionOpCode:
    if op.name.startswith("OP_NOP"):
        _ = register_op(op)(op_nop)


def op_immediate(stack: Stack, current_op: TransactionOpCode):
    stack.append(encode_num(_IMMEDIATE_OP_TABLE[current_op]))


# batch register immediate opcodes
for op in _IMMEDIATE_OP_TABLE:
    _ = register_op(op)(op_immediate)


@register_op(TransactionOpCode.OP_IF, TransactionOpCode.OP_NOTIF)
@assert_stack_size(1)
def op_if(stack: Stack, cmds: Commands, current_op: TransactionOpCode):
    branch_true_commands: Commands = deque()
    branch_false_commands: Commands = deque()
    current_branch = branch_true_commands
    found = False
    num_endif_needed = 1
    while cmds:  # go through and re-make the items array based on the top stack element
        match item := cmds.popleft():
            case TransactionOpCode.OP_IF | TransactionOpCode.OP_NOTIF:
                # nested if, we have to go another endif
                num_endif_needed += 1
            case TransactionOpCode.OP_ELSE if num_endif_needed == 1:
                current_branch = branch_false_commands
                continue
            case TransactionOpCode.OP_ENDIF if num_endif_needed == 1:
                found = True
                break
            case TransactionOpCode.OP_ENDIF:
                num_endif_needed -= 1
            case _:
                pass
        current_branch.append(item)
    if not found:
        raise OpCodeRejectedError("Unmatched OP_IF")
    condition = decode_num(stack.pop())
    if (current_op is TransactionOpCode.OP_IF) != bool(condition):
        cmds.extendleft(reversed(branch_false_commands))
    else:
        cmds.extendleft(reversed(branch_true_commands))


@register_op(TransactionOpCode.OP_VERIFY)
@assert_stack_size(1)
def op_verify(stack: Stack):
    element = stack.pop()
    if decode_num(element) == 0:
        raise OpCodeRejectedError(f"Verify {element=} failed")


@register_op(TransactionOpCode.OP_RETURN)
def op_return(stack: Stack):  # pyright:ignore[reportUnusedParameter] # noqa: ARG001
    raise OpCodeRejectedError("OP_RETURN executed")


@register_op(TransactionOpCode.OP_TOALTSTACK)
@assert_stack_size(1)
def op_toaltstack(stack: Stack, alt_stack: Stack):
    alt_stack.append(stack.pop())


@register_op(TransactionOpCode.OP_FROMALTSTACK)
def op_fromaltstack(stack: Stack, alt_stack: Stack):
    if not alt_stack:
        raise InsufficientStackError
    stack.append(alt_stack.pop())


@register_op(TransactionOpCode.OP_DROP, TransactionOpCode.OP_2DROP)
def op_drop_n(stack: Stack, current_op: TransactionOpCode):
    drop_num = {
        TransactionOpCode.OP_DROP: 1,
        TransactionOpCode.OP_2DROP: 2,
    }[current_op]
    if len(stack) < drop_num:
        raise InsufficientStackError
    for _ in range(drop_num):
        _ = stack.pop()


@register_op(
    TransactionOpCode.OP_DUP, TransactionOpCode.OP_2DUP, TransactionOpCode.OP_3DUP
)
def op_dup_n(stack: Stack, current_op: TransactionOpCode):
    dup_num = {
        TransactionOpCode.OP_DUP: 1,
        TransactionOpCode.OP_2DUP: 2,
        TransactionOpCode.OP_3DUP: 3,
    }[current_op]
    if len(stack) < dup_num:
        raise InsufficientStackError
    stack.extend([stack[-i] for i in range(dup_num, 0, -1)])


@register_op(TransactionOpCode.OP_OVER)
@assert_stack_size(2)
def op_over(stack: Stack):
    stack.append(stack[-2])


@register_op(TransactionOpCode.OP_2OVER)
@assert_stack_size(4)
def op_2over(stack: Stack):
    stack.extend([stack[-4], stack[-3]])


@register_op(TransactionOpCode.OP_ROT)
@assert_stack_size(3)
def op_rot(stack: Stack):
    elements = [stack.pop() for _ in range(3)][::-1]
    stack.extend(elements[1:] + elements[:1])


@register_op(TransactionOpCode.OP_2ROT)
@assert_stack_size(6)
def op_2rot(stack: Stack):
    elements = [stack.pop() for _ in range(6)][::-1]
    stack.extend(elements[2:] + elements[:2])


@register_op(TransactionOpCode.OP_SWAP)
@assert_stack_size(2)
def op_swap(stack: Stack):
    element1 = stack.pop()
    element2 = stack.pop()
    stack.extend([element1, element2])


@register_op(TransactionOpCode.OP_2SWAP)
@assert_stack_size(4)
def op_2swap(stack: Stack):
    elements = [stack.pop() for _ in range(4)][::-1]
    stack.extend(elements[2:] + elements[:2])


@register_op(TransactionOpCode.OP_IFDUP)
@assert_stack_size(1)
def op_ifdup(stack: Stack):
    element = stack[-1]
    if decode_num(element) != 0:
        stack.append(element)


@register_op(TransactionOpCode.OP_NIP)
@assert_stack_size(2)
def op_nip(stack: Stack):
    elements = [stack.pop(), stack.pop()]
    stack.append(elements[1])


@register_op(TransactionOpCode.OP_PICK)
@assert_stack_size(1)
def op_pick(stack: Stack):
    n = decode_num(stack.pop())
    if n < 0 or n >= len(stack):
        raise InsufficientStackError
    stack.append(stack[-n - 1])


@register_op(TransactionOpCode.OP_ROLL)
@assert_stack_size(1)
def op_roll(stack: Stack):
    n = decode_num(stack.pop())
    if n < 0 or n >= len(stack):
        raise InsufficientStackError
    if n == 0:
        return
    elements = [stack.pop() for _ in range(n)][::-1]
    stack.extend(elements[1:] + elements[:1])


@register_op(TransactionOpCode.OP_TUCK)
@assert_stack_size(2)
def op_tuck(stack: Stack):
    elements = [stack.pop(), stack.pop()]
    stack.extend([*elements, elements[0]])


@register_op(TransactionOpCode.OP_SIZE)
@assert_stack_size(1)
def op_size(stack: Stack):
    stack.append(encode_num(len(stack[-1])))


@register_op(TransactionOpCode.OP_DEPTH)
def op_depth(stack: Stack):
    stack.append(encode_num(len(stack)))


@register_op(TransactionOpCode.OP_EQUAL)
@assert_stack_size(2)
def op_equal(stack: Stack):
    element1 = stack.pop()
    element2 = stack.pop()
    stack.append(encode_num(element1 == element2))


@register_op(TransactionOpCode.OP_EQUALVERIFY)
def op_equalverify(stack: Stack):
    op_equal(stack)
    op_verify(stack)


@register_op(
    TransactionOpCode.OP_1ADD,
    TransactionOpCode.OP_1SUB,
    TransactionOpCode.OP_NEGATE,
    TransactionOpCode.OP_ABS,
    TransactionOpCode.OP_NOT,
    TransactionOpCode.OP_0NOTEQUAL,
)
@assert_stack_size(1)
def op_arithmetic_unary(stack: Stack, current_op: TransactionOpCode):
    element = stack.pop()
    num = decode_num(element)
    match current_op:
        case TransactionOpCode.OP_1ADD:
            num += 1
        case TransactionOpCode.OP_1SUB:
            num -= 1
        case TransactionOpCode.OP_NEGATE:
            num = -num
        case TransactionOpCode.OP_ABS:
            num = abs(num)
        case TransactionOpCode.OP_NOT:
            num = int(num == 0)
        case TransactionOpCode.OP_0NOTEQUAL:
            num = int(num != 0)
        case _:  # pragma: no cover
            raise ValueError(f"Invalid opcode: {current_op}")
    stack.append(encode_num(num))


@register_op(
    TransactionOpCode.OP_ADD,
    TransactionOpCode.OP_SUB,
    TransactionOpCode.OP_BOOLAND,
    TransactionOpCode.OP_BOOLOR,
    TransactionOpCode.OP_NUMEQUAL,
    TransactionOpCode.OP_NUMEQUALVERIFY,
    TransactionOpCode.OP_NUMNOTEQUAL,
    TransactionOpCode.OP_LESSTHAN,
    TransactionOpCode.OP_GREATERTHAN,
    TransactionOpCode.OP_LESSTHANOREQUAL,
    TransactionOpCode.OP_GREATERTHANOREQUAL,
    TransactionOpCode.OP_MIN,
    TransactionOpCode.OP_MAX,
)
@assert_stack_size(2)
def op_arithmetic_binary(stack: Stack, current_op: TransactionOpCode):  # noqa: C901, PLR0912
    b, a = map(decode_num, (stack.pop(), stack.pop()))
    match current_op:
        case TransactionOpCode.OP_ADD:
            result = a + b
        case TransactionOpCode.OP_SUB:
            result = a - b
        case TransactionOpCode.OP_BOOLAND:
            result = int(bool(a) and bool(b))
        case TransactionOpCode.OP_BOOLOR:
            result = int(bool(a) or bool(b))
        case TransactionOpCode.OP_NUMEQUAL:
            result = int(a == b)
        case TransactionOpCode.OP_NUMEQUALVERIFY:
            result = int(a == b)
            stack.append(encode_num(result))
            op_verify(stack)
            return
        case TransactionOpCode.OP_NUMNOTEQUAL:
            result = int(a != b)
        case TransactionOpCode.OP_LESSTHAN:
            result = int(a < b)
        case TransactionOpCode.OP_GREATERTHAN:
            result = int(a > b)
        case TransactionOpCode.OP_LESSTHANOREQUAL:
            result = int(a <= b)
        case TransactionOpCode.OP_GREATERTHANOREQUAL:
            result = int(a >= b)
        case TransactionOpCode.OP_MIN:
            result = min(a, b)
        case TransactionOpCode.OP_MAX:
            result = max(a, b)
        case _:  # pragma: no cover
            raise ValueError(f"Invalid opcode: {current_op}")
    stack.append(encode_num(result))


@register_op(TransactionOpCode.OP_WITHIN)
@assert_stack_size(3)
def op_within(stack: Stack):
    maximum, minimum, x = map(decode_num, (stack.pop(), stack.pop(), stack.pop()))
    stack.append(encode_num(minimum <= x < maximum))


@register_op(
    TransactionOpCode.OP_RIPEMD160,
    TransactionOpCode.OP_SHA1,
    TransactionOpCode.OP_SHA256,
    TransactionOpCode.OP_HASH160,
    TransactionOpCode.OP_HASH256,
)
@assert_stack_size(1)
def op_hash(stack: Stack, current_op: TransactionOpCode):
    element = stack.pop()
    match current_op:
        case TransactionOpCode.OP_RIPEMD160:
            result = ripemd160(element)
        case TransactionOpCode.OP_SHA1:
            result = sha1(element)
        case TransactionOpCode.OP_SHA256:
            result = sha256(element)
        case TransactionOpCode.OP_HASH160:
            result = ripemd160(sha256(element))
        case TransactionOpCode.OP_HASH256:
            result = sha256(sha256(element))
        case _:  # pragma: no cover
            raise ValueError(f"Invalid opcode: {current_op}")
    stack.append(result)


@register_op(TransactionOpCode.OP_CHECKSIG)
@assert_stack_size(2)
def op_checksig(stack: Stack, z: bytes):
    pk = stack.pop()
    signature = stack.pop()
    if signature[-1] != SignatureHashTypes.ALL:
        raise OpCodeRejectedError("Invalid signature hash type")
    stack.append(encode_num(verify_signature(pk, signature[:-1], z)))


@register_op(TransactionOpCode.OP_CHECKSIGVERIFY)
def op_checksigverify(stack: Stack, z: bytes):
    op_checksig(stack, z)
    op_verify(stack)


@register_op(TransactionOpCode.OP_CHECKMULTISIG)
@assert_stack_size(1)
def op_checkmultisig(stack: Stack, z: bytes):
    n = decode_num(stack.pop())
    if len(stack) <= n:
        raise InsufficientStackError
    public_keys = [stack.pop() for _ in range(n)]
    m = decode_num(stack.pop())
    if len(stack) <= m:
        raise InsufficientStackError
    signatures = [stack.pop() for _ in range(m)]
    if any(sig[-1] != SignatureHashTypes.ALL for sig in signatures):
        raise OpCodeRejectedError("Invalid signature hash type")
    # Due to a bug, one extra unused value is removed from the stack.
    _ = stack.pop()
    if not public_keys or not signatures:
        raise OpCodeRejectedError("Invalid public keys or signatures")
    passed = all(
        any(verify_signature(pk, sig[:-1], z) for pk in public_keys)
        for sig in signatures
    )
    stack.append(encode_num(passed))


@register_op(TransactionOpCode.OP_CHECKMULTISIGVERIFY)
def op_checkmultisigverify(stack: Stack, z: bytes):
    op_checkmultisig(stack, z)
    op_verify(stack)


# TODO: Implement the following opcodes
# https://github.com/jimmysong/programmingbitcoin/blob/master/code-ch06/op.py#L686-L718
# - OP_CHECKLOCKTIMEVERIFY
# - OP_CHECKSEQUENCEVERIFY


def evaluate_script(script: BaseTransactionScript, z: bytes, execution_limit: int = -1):
    """Evaluate a transaction script by processing its commands sequentially.

    This function implements the Bitcoin Script evaluation logic, processing opcodes
    and managing the execution stack. It handles both data pushing operations and
    opcode execution according to the Bitcoin protocol rules.

    Args:
        script (TransactionScript): The script to be evaluated containing commands.
        z (bytes): Transaction signature hash that may be used in signature checks.
        execution_limit (int): Maximum number of operations to execute. -1 for
            unlimited. Default is -1.

    Returns:
        tuple[int, deque[bytes]]: A tuple containing:
            - Number of operations executed (int)
            - Final state of the execution stack (deque[bytes])

    Raises:
        OpCodeRejectedError: If an unknown opcode is encountered or execution limit is
            reached.

    Example:
        >>> script = TransactionScript([OP_TRUE, OP_VERIFY])
        >>> total_ops, result_stack = evaluate_script(script, b'')

    """
    stack = deque[bytes]()
    commands = deque(script.commands)
    alternative_args: dict[OpCodeInstructArguments, Any] = {  # pyright:ignore[reportExplicitAny]
        OpCodeInstructArguments.cmds: commands,
        OpCodeInstructArguments.alt_stack: deque[bytes](),
        OpCodeInstructArguments.z: z,
    }
    total_executions = 0
    while commands:
        command = commands.popleft()
        if (total_executions := total_executions + 1) == execution_limit:
            raise OpCodeRejectedError("Execution limit reached")
        alternative_args[OpCodeInstructArguments.current_op] = command
        if isinstance(command, bytes):
            stack.append(command)
            continue
        if (result := _TRANSACTION_OP_TABLE.get(command)) is None:
            raise OpCodeRejectedError(f"Unknown opcode: {command}")
        callback, flags = result
        kwargs = {
            arg.name: alternative_args[arg]
            for arg in flags
            if (arg.name is not None) and (arg is not OpCodeInstructArguments.stack)
        }
        callback(stack, **kwargs)
    return total_executions, stack
