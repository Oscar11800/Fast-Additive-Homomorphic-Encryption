import secrets
import fahe1
from enum import Enum


class Operation(Enum):
    TIMED_KEYGEN = 1
    TIMED_ENCODE = 2
    CYPHERTEXT_ENCODE = 3
    DECODE = 4


def get_op_func_map():
    """
    Define the mapping of operations to FAHE1 function calls.
    """
    operations_map = {
        Operation.TIMED_KEYGEN: (
            fahe1.timed_keygen1,
            ["l", "m_max", "alpha"],
        ),
        Operation.TIMED_ENCODE: (
            fahe1.timed_enc1,
            ["l", "m_max", "alpha", "m"],
        ),
        Operation.CYPHERTEXT_ENCODE: (
            fahe1.length_enc1,
            ["l", "m_max", "alpha", "m"],
        ),
        Operation.DECODE: (
            fahe1.dec1,
            ["dk", "c"],
        ),
    }
    return operations_map


def collect_security_param_performance(
    start_lambda: int, end_lambda: int, step: int, op: Operation, func_map, params
) -> dict[int, float]:
    """
    Collects datapoints of security parameter (lambda) vs. time performance of keygen, encrypt, or decrypt operations.

    Args:
        start_lambda(int): lambda to start collecting time_performance
        end_lambda(int): lambda to end collecting time_performance
        step(int): step to increment cur_lambda (x-distance b/t datapoints)
        op(Operation): fahe1 operation to test
        func_map: dictionary of fahe1 functions
        params: parameters to pass into func_map

    Returns:
        data_points(dict[int, float]): dictionary of lambda - performance key-value pairs
    """
    if op not in func_map:
        raise ValueError("Unsupported operation")

    # Retrieve the function and its parameter names from the function map
    func, param_names = func_map[op]

    cur_lambda = start_lambda
    data_points = {}

    for i in range(cur_lambda, end_lambda + 1, step):
        # Construct arguments based on parameter names
        args = {}
        for name in param_names:
            if name in params:
                args[name] = params[name]

        # Call the function with dynamically constructed arguments
        if op == Operation.TIMED_KEYGEN:
            time_performance = func(
                cur_lambda, params.get("m_max", 32), params.get("alpha", 6)
            )
        elif op == Operation.ENCODE:
            time_performance = func(
                cur_lambda,
                params.get("m_max", 32),
                params.get("alpha", 6),
                params.get("m", secrets.randbelow(2**32 - 1)),
            )
        else:
            argument_values = list(args.values())
            time_performance = func(*argument_values)

        # Add data point to resulting dictionary
        data_points[cur_lambda] = time_performance
        cur_lambda += step

    return data_points


def collect_security_param_ciphertext(
    start_lambda: int, end_lambda: int, step: int, params
) -> dict[int, int]:
    """
    Collects datapoints of security parameter (lambda) vs. ciphertext bit size.

    Args:
        start_lambda(int): lambda to start collecting time_performance
        end_lambda(int): lambda to end collecting time_performance
        step(int): step to increment cur_lambda (x-distance b/t datapoints)
        params: parameters to pass into func_map

    Returns:
        data_points(dict[int, int]): dictionary of lambda - ciphertext bitsize key-value pairs
    """

    # Retrieve the function and its parameter names from the function map
    func_map = get_op_func_map()
    func, param_names = func_map[Operation.CYPHERTEXT_ENCODE]

    data_points = {}

    for cur_lambda in range(start_lambda, end_lambda + 1, step):
        args = {name: params.get(name) for name in param_names}
        if 'm' in args and args['m'] is None:
            args['m'] = secrets.randbelow(2**params.get("m_max", 32) - 1)
        args['l'] = cur_lambda
        cipher_text_size = func(**args)

        data_points[cur_lambda] = cipher_text_size
        cur_lambda += step

    return data_points


def print_data_points(data_points: dict[int, float]):
    for key, value in data_points.items():
        print(f"{key} : {value:.8f}")
