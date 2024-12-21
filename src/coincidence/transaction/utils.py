from io import BytesIO

from base58 import b58decode_check

from .types import Transaction, TransactionOpCode, TransactionScript
from .vm import OpCodeRejectedError, Stack, decode_num, evaluate_script


def p2pkh_script(hash160: bytes | str):
    """Create a Pay-to-Public-Key-Hash (P2PKH) script from a given hash.

    P2PKH is a standard Bitcoin transaction script that enables sending bitcoins to a
    specific bitcoin address. The script ensures that only the owner of the private key
    corresponding to the public key hash can spend the funds.

    Args:
        hash160: Either a raw bytes public key hash or a
            base58-encoded Bitcoin address string. If a string is provided, it will be
            base58 decoded and the version byte will be stripped.

    Returns: A TransactionScript object representing the P2PKH script

    Raises:
        ValueError: If the base58 decoding fails for string input

    """
    if isinstance(hash160, str):
        hash160 = b58decode_check(hash160)[1:]
    return TransactionScript.from_commands(
        [
            TransactionOpCode.OP_DUP,
            TransactionOpCode.OP_HASH160,
            hash160,
            TransactionOpCode.OP_EQUALVERIFY,
            TransactionOpCode.OP_CHECKSIG,
        ]
    )


class TransactionValidationError(ValueError):
    pass


def validate_transaction_scripts(
    transaction: Transaction,
    pubkey_scripts: list[bytes | TransactionScript],
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
    for i, pk in enumerate(pubkey_scripts):
        script = (
            TransactionScript.deserialize(BytesIO(pk)) if isinstance(pk, bytes) else pk
        )
        z = transaction.signature_hash(i, script)
        combined_script = transaction.inputs[i].script_signature + script
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