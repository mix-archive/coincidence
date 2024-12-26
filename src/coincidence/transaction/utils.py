from collections.abc import Sequence

from .types.common import decode_num
from .types.script import BaseTransactionScript
from .types.transaction import Transaction
from .vm import OpCodeRejectedError, Stack, evaluate_script


class TransactionValidationError(ValueError):
    pass


def validate_transaction_scripts(
    transaction: Transaction,
    pubkey_scripts: Sequence[BaseTransactionScript],
    *,
    execution_limit: int = 1000,
):
    """Validate a bitcoin transaction.

    This function only validates the script signatures for each input in the
    transaction. It does not check the transaction itself for correctness
    (e.g. inputs sum to outputs).

    Args:
        transaction (Transaction): The transaction to validate
        pubkey_scripts (list[bytes | TransactionScript]): List of public key scripts
            corresponding to each input. Can be raw bytes or TransactionScript objects
        execution_limit (int, optional): Maximum number of script operations to allow.
            Defaults to 1000.

    Returns:
        bool: True if transaction is valid

    Raises:
        TransactionValidationError: If number of pubkey scripts doesn't match inputs,
            if script execution is rejected, or if final stack validation fails

    Examples:
        >>> tx = Transaction(...)
        >>> pubkey_scripts = [script1, script2]
        >>> validate_transaction(tx, pubkey_scripts)
        True

    """
    if len(transaction.inputs) != len(pubkey_scripts):
        raise TransactionValidationError(
            "Number of pubkey scripts does not match number of inputs"
        )
    for i, (input_, script) in enumerate(
        zip(transaction.inputs, pubkey_scripts, strict=True)
    ):
        z = transaction.signature_hash(i, script)
        if (script_sig := input_.script_signature) is None:
            raise TransactionValidationError("Missing script signature")
        combined_script = script_sig + script
        try:
            _, stack = evaluate_script(
                combined_script, z, execution_limit=execution_limit
            )
        except OpCodeRejectedError as e:
            raise TransactionValidationError("Script evaluation rejected") from e
        if not validate_stack(stack):
            raise TransactionValidationError("Script validation failed")
    return True


def validate_stack(stack: Stack):
    """Validate the stack for a given script.

    The stack is valid if it contains at least one element and the top element is not 0.
    """
    return bool(len(stack) and decode_num(stack.pop()) != 0)
