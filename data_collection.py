import secrets
import fahe1
from enum import Enum
import csv
import time
from fahe1 import keygen1, enc1, dec1
import math
from fahe2 import dec2, enc2, keygen2


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
        elif op == Operation.TIMED_ENCODE:
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


def collect_alpha_performance(
    start_alpha: int, end_alpha: int, step: int, op: Operation, func_map, params
) -> dict[int, float]:
    """
    Collects datapoints of alpha vs. time performance of keygen, encrypt, or decrypt operations.

    Args:
        start_alpha(int): alpha to start collecting time_performance
        end_alpha(int): alpha to end collecting time_performance
        step(int): step to increment cur_alpha (x-distance b/t datapoints)
        op(Operation): fahe1 operation to test
        func_map: dictionary of fahe1 functions
        params: parameters to pass into func_map

    Returns:
        data_points(dict[int, float]): dictionary of alpha - performance key-value pairs
    """
    if op not in func_map:
        raise ValueError("Unsupported operation")

    # Retrieve the function and its parameter names from the function map
    func, param_names = func_map[op]

    cur_alpha = start_alpha
    data_points = {}

    for i in range(cur_alpha, end_alpha + 1, step):
        # Construct arguments based on parameter names
        args = {}
        for name in param_names:
            if name in params:
                args[name] = params[name]

        # Call the function with dynamically constructed arguments
        if op == Operation.TIMED_KEYGEN:
            time_performance = func(
                cur_alpha, params.get("m_max", 32), params.get("lambda", 32)
            )
        elif op == Operation.TIMED_ENCODE:
            time_performance = func(
                params.get("lambda", 32),
                params.get("m_max", 32),
                cur_alpha,
                params.get("m", secrets.randbelow(2**32 - 1)),
            )
        else:
            argument_values = list(args.values())
            time_performance = func(*argument_values)

        # Add data point to resulting dictionary
        data_points[cur_alpha] = time_performance
        cur_alpha += step

    return data_points


def collect_m_max_performance(
    start_m_max: int, end_m_max: int, step: int, op: Operation, func_map, params
) -> dict[int, float]:
    """
    Collects datapoints of m_max vs. time performance of keygen, encrypt, or decrypt operations.

    Args:
        start_m_max(int): m_max to start collecting time_performance
        end_m_max(int): m_max to end collecting time_performance
        step(int): step to increment cur_m_max (x-distance b/t datapoints)
        op(Operation): fahe1 operation to test
        func_map: dictionary of fahe1 functions
        params: parameters to pass into func_map

    Returns:
        data_points(dict[int, float]): dictionary of m_max - performance key-value pairs
    """
    if op not in func_map:
        raise ValueError("Unsupported operation")

    # Retrieve the function and its parameter names from the function map
    func, param_names = func_map[op]

    cur_m_max = start_m_max
    data_points = {}

    for i in range(cur_m_max, end_m_max + 1, step):
        # Construct arguments based on parameter names
        args = {}
        for name in param_names:
            if name in params:
                args[name] = params[name]

        # Call the function with dynamically constructed arguments
        if op == Operation.TIMED_KEYGEN:
            time_performance = func(
                params.get("alpha", 6), cur_m_max, params.get("lambda", 32)
            )
        elif op == Operation.TIMED_ENCODE:
            time_performance = func(
                params.get("lambda", 32),
                cur_m_max,
                params.get("alha", 32),
                params.get("m", secrets.randbelow(2**32 - 1)),
            )
        else:
            argument_values = list(args.values())
            time_performance = func(*argument_values)

        # Add data point to resulting dictionary
        data_points[cur_m_max] = time_performance
        cur_m_max += step

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
        if "m" in args and args["m"] is None:
            args["m"] = secrets.randbelow(2 ** params.get("m_max", 32) - 1)
        args["l"] = cur_lambda
        cipher_text_size = func(**args)

        data_points[cur_lambda] = cipher_text_size
        cur_lambda += step

    return data_points


def print_data_points(data_points: dict[int, float]):
    for key, value in data_points.items():
        print(f"{key} : {value:.8f}")


def output_csv_6(
    x_list,
    y1_list,
    y2_list,
    y3_list,
    y4_list,
    y5_list,
    x_name=None,
    y1_name=None,
    y2_name=None,
    y3_name=None,
    y4_name=None,
    y5_name=None,
    file_name="output_data",
):
    """
    x_list, y1_list, y2_list: list of independent and dependent variables
    x_name, y1_name, y2_name: string of headers
    file_name: string of filename, not including the ".csv"
    """
    output_file = "{}.csv".format(file_name)
    with open(output_file, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            [x_name, y1_name, y2_name, y3_name, y4_name, y5_name]
        )  # Write header
        for x, y1, y2, y3, y4, y5 in zip(
            x_list, y1_list, y2_list, y3_list, y4_list, y5_list
        ):
            writer.writerow([x, y1, y2, y3, y4, y5])
    print(f"CSV file '{output_file}' created successfully.")


def output_csv_11(
    x_list,
    y1_list,
    y2_list,
    y3_list,
    y4_list,
    y5_list,
    y6_list,
    y7_list,
    y8_list,
    y9_list,
    y10_list,
    x_name=None,
    y1_name=None,
    y2_name=None,
    y3_name=None,
    y4_name=None,
    y5_name=None,
    y6_name=None,
    y7_name=None,
    y8_name=None,
    y9_name=None,
    y10_name=None,
    file_name="output_data",
):
    output_file = "{}.csv".format(file_name)
    with open(output_file, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                x_name,
                y1_name,
                y2_name,
                y3_name,
                y4_name,
                y5_name,
                y6_name,
                y7_name,
                y8_name,
                y9_name,
                y10_name,
            ]
        )  # Write header
        for x, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10 in zip(
            x_list,
            y1_list,
            y2_list,
            y3_list,
            y4_list,
            y5_list,
            y6_list,
            y7_list,
            y8_list,
            y9_list,
            y10_list,
        ):
            writer.writerow([x, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10])
    print(f"CSV file '{output_file}' created successfully.")


def lambda_performance_1(lambda_start, lambda_end, lambda_step, rep, m_max, alpha, m):
    lambdas = []
    keygen_times = []
    enc_times = []
    dec_times = []
    total_times = []
    clengths = []
    l = lambda_start
    while l <= lambda_end:
        keygen_time = []
        enc_time = []
        dec_time = []
        clength = 0
        lambdas.append(l)
        for i in range(rep):
            keygen_tik = time.time()
            k, ek, dk = keygen1(l, m_max, alpha)
            keygen_tok = time.time()
            keygen_time.append(keygen_tok - keygen_tik)
            enc_tik = time.time()
            c = enc1(ek, m)
            clength += c.bit_length()
            enc_tok = time.time()
            enc_time.append(enc_tok - enc_tik)
            dec_tik = time.time()
            m_outcome = dec1(dk, c)
            dec_tok = time.time()
            dec_time.append(dec_tok - dec_tik)

        average_keygen_time = sum(keygen_time) / rep
        keygen_times.append(average_keygen_time)
        average_enc_time = sum(enc_time) / rep
        enc_times.append(average_enc_time)
        average_dec_time = sum(dec_time) / rep
        dec_times.append(average_dec_time)
        total_time = average_keygen_time + average_enc_time + average_dec_time
        total_times.append(total_time)
        clengths.append(clength / rep)

        l += lambda_step
    return lambdas, keygen_times, enc_times, dec_times, total_times, clengths


def m_max_performance_1(m_max_start, m_max_end, m_max_step, rep, l, alpha, m):
    m_maxs = []
    keygen_times = []
    enc_times = []
    dec_times = []
    total_times = []
    clengths = []
    m_max = m_max_start
    while m_max <= m_max_end:
        keygen_time = []
        enc_time = []
        dec_time = []
        clength = 0
        m_maxs.append(m_max)
        for i in range(rep):
            keygen_tik = time.time()
            k, ek, dk = keygen1(l, m_max, alpha)
            keygen_tok = time.time()
            keygen_time.append(keygen_tok - keygen_tik)
            enc_tik = time.time()
            c = enc1(ek, m)
            clength += c.bit_length()
            enc_tok = time.time()
            enc_time.append(enc_tok - enc_tik)
            dec_tik = time.time()
            m_outcome = dec1(dk, c)
            dec_tok = time.time()
            dec_time.append(dec_tok - dec_tik)

        average_keygen_time = sum(keygen_time) / rep
        keygen_times.append(average_keygen_time)
        average_enc_time = sum(enc_time) / rep
        enc_times.append(average_enc_time)
        average_dec_time = sum(dec_time) / rep
        dec_times.append(average_dec_time)
        total_time = average_keygen_time + average_enc_time + average_dec_time
        total_times.append(total_time)
        clengths.append(clength / rep)

        m_max += m_max_step
    return m_maxs, keygen_times, enc_times, dec_times, total_times, clengths


def alpha_performance_1(alpha_start, alpha_end, alpha_step, rep, l, m_max, m):
    """
    Measures the performance of the FAHE2 scheme for various alpha values.

    Parameters:
    alpha_start (int): Starting value of alpha.
    alpha_end (int): Ending value of alpha.
    alpha_step (int): Step value to increment alpha.
    rep (int): Number of repetitions for averaging.
    l (int): Security parameter lambda.
    m_max (int): Maximum message size.
    m (int): Message to be encrypted.

    Returns:
    tuple: Contains lists of alphas, rhos, etas, gammas, keygen times, 
           encryption times, decryption times, total times, ciphertext lengths, 
           lambdas, and m_max values.
    """
    alphas = []
    rhos = []
    etas = []
    gammas = []
    keygen_times = []
    enc_times = []
    dec_times = []
    total_times = []
    clengths = []
    lambdas = []
    m_maxes = []
    alpha = alpha_start
    while alpha <= alpha_end:
        print("alpha = {}".format(alpha))
        rho = l
        eta = rho + 2 * alpha + m_max
        gamma = math.ceil(rho / math.log2(rho) * ((eta - rho) ** 2))
        keygen_time = []
        enc_time = []
        dec_time = []
        clength = 0
        alphas.append(alpha)
        for i in range(rep):
            keygen_tik = time.time()
            k, ek, dk = keygen1(l, m_max, alpha)
            keygen_tok = time.time()
            keygen_time.append((keygen_tok - keygen_tik) * 1000)
            enc_tik = time.time()
            c = enc1(ek, m)
            clength += c.bit_length()
            enc_tok = time.time()
            enc_time.append(((enc_tok - enc_tik) * 1000))
            dec_tik = time.time()
            m_outcome = dec1(dk, c) #run decrypt to time it, no verification
            dec_tok = time.time()
            dec_time.append(((dec_tok - dec_tik) * 1000))

        rhos.append(rho)
        etas.append(eta)
        gammas.append(gamma)
        average_keygen_time = sum(keygen_time) / rep
        keygen_times.append(round(float(average_keygen_time), 4))
        average_enc_time = sum(enc_time) / rep
        enc_times.append(round(float(average_enc_time), 4))
        average_dec_time = sum(dec_time) / rep
        dec_times.append(round(float(average_dec_time), 4))
        total_time = average_keygen_time + average_enc_time + average_dec_time
        total_times.append(round(float(total_time), 4))
        clengths.append(round(clength / rep))
        lambdas.append(l)
        m_maxes.append(m_max)

        alpha += alpha_step
    return (
        alphas,
        rhos,
        etas,
        gammas,
        keygen_times,
        enc_times,
        dec_times,
        total_times,
        clengths,
        lambdas,
        m_maxes,
    )


def alpha_performance_2(alpha_start, alpha_end, alpha_step, rep, l, m_max, m):
    """
    Measures the performance of the FAHE2 scheme for various alpha values.

    Parameters:
    alpha_start (int): Starting value of alpha.
    alpha_end (int): Ending value of alpha.
    alpha_step (int): Step value to increment alpha.
    rep (int): Number of repetitions for averaging.
    l (int): Security parameter lambda.
    m_max (int): Maximum message size.
    m (int): Message to be encrypted.

    Returns:
    tuple: Contains lists of alphas, rhos, etas, gammas, keygen times, 
           encryption times, decryption times, total times, ciphertext lengths, 
           lambdas, and m_max values.
    """
    alphas = []
    rhos = []
    etas = []
    gammas = []
    keygen_times = []
    enc_times = []
    dec_times = []
    total_times = []
    clengths = []
    lambdas = []
    m_maxes = []
    alpha = alpha_start
    while alpha <= alpha_end:
        print("alpha = {}".format(alpha))
        rho = l
        eta = rho + 2 * alpha + m_max
        gamma = math.ceil(rho / math.log2(rho) * ((eta - rho) ** 2))
        keygen_time = []
        enc_time = []
        dec_time = []
        clength = 0
        alphas.append(alpha)
        for i in range(rep):
            keygen_tik = time.time()
            k, ek, dk = keygen2(l, m_max, alpha)
            keygen_tok = time.time()
            keygen_time.append((keygen_tok - keygen_tik) * 1000)
            enc_tik = time.time()
            c = enc2(ek, m)
            clength += c.bit_length()
            enc_tok = time.time()
            enc_time.append(((enc_tok - enc_tik) * 1000))
            dec_tik = time.time()
            m_outcome = dec2(dk, c)
            dec_tok = time.time()
            dec_time.append(((dec_tok - dec_tik) * 1000))

        rhos.append(rho)
        etas.append(eta)
        gammas.append(gamma)
        average_keygen_time = sum(keygen_time) / rep
        keygen_times.append(round(float(average_keygen_time), 4))
        average_enc_time = sum(enc_time) / rep
        enc_times.append(round(float(average_enc_time), 4))
        average_dec_time = sum(dec_time) / rep
        dec_times.append(round(float(average_dec_time), 4))
        total_time = average_keygen_time + average_enc_time + average_dec_time
        total_times.append(round(float(total_time), 4))
        clengths.append(round(clength / rep))
        lambdas.append(l)
        m_maxes.append(m_max)

        alpha += alpha_step
    return (
        alphas,
        rhos,
        etas,
        gammas,
        keygen_times,
        enc_times,
        dec_times,
        total_times,
        clengths,
        lambdas,
        m_maxes,
    )
