import random
from fahe1 import keygen1, enc1, dec1
import matplotlib.pyplot as plt

from fahe2 import dec2, enc2

# Printing values
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# HOW TO USE: CHANGE THE HARD VALUES AND RUN: `python3 test_additivity2.py`

# HARD VALUES; Make changes here, code will take care of the rest
LAMBDA_PARAM = 128  # security param (normally 128 or 256)
M_MAX = 32  # max size of msgs in bits (normally 32 or 64)
ALPHA = 6  # determines num_additions
NUM_ADDITIONS = 2 ** (ALPHA - 1)  # normally max is 2**(ALPHA-1)
NUM_TRIALS = 25  # how many times you want to test -1
MSG_SIZE = 32  # optional, normally same as M_MAX
ENCRYPTION_SCHEME = 2  # 1 for FAHE1, 2 for FAHE2, else error


# NOT SO HARD VALUES, DON'T TOUCH
success_number = 0  # number of successful tests
pass_indices = []  # stores test indices that passed addition
fail_indices = []  # stores test indices that failed addition
passed_equal_sums = []  # stores ciphertext = msg equalities
failed_msg_sums = []  # stores failed msg totals
failed_decrypted_ciph_sums = []  # stores failed decryp ciphtext totals

# KEYGEN
key = keygen1(LAMBDA_PARAM, M_MAX, ALPHA)
encrypt_key = (key[1][0], key[1][1], key[1][2], key[1][3])
decrypt_key = (key[2][0], key[2][1], key[2][2], key[2][3])


# NOTE: If you want to generate a single preset message, go to the add_fahe1() method and change: is_single_msg = True , msg = whateveryouwanttohardset
def populate_message_list(
    num_msgs: int, is_single_msg: bool = False, msg: int = random.getrandbits(MSG_SIZE)
):
    """
    Populate a list of random messages.

    Args:
        num_msgs (int): Number of messages to generate.
        is_single_msg (bool): Whether to use a single message for all entries.
        msg (int): A specific message to use if is_single_msg is True.

    Returns:
        list[int]: List of generated messages.
    """
    if is_single_msg:
        return [msg] * num_msgs
    else:
        return [random.getrandbits(MSG_SIZE) for _ in range(num_msgs)]


def fahe1_populate_ciph_list(msg_list: list[int]):
    """Encrypt a list of messages with fahe1 encryption scheme."""
    return [enc1(encrypt_key, m) for m in msg_list]


def fahe2_populate_ciph_list(msg_list: list[int]):
    """Encrypt a list of messages with fahe1 encryption scheme."""
    return [enc2(encrypt_key, m) for m in msg_list]


def get_msg_sum(msg_list: list[int]):
    """Calculate the direct sum of a list of messages."""
    return sum(msg_list)


def get_ciph_sum(c_list: list[int]):
    """Calculate the sum of a list of ciphertexts."""
    return sum(c_list)


def fahe1_get_decrypted_sum(ciph_sum: int):
    """Decrypt a summed ciphertext with fahe1 decryption scheme."""
    return dec1(decrypt_key, ciph_sum)


def fahe2_get_decrypted_sum(ciph_sum: int):
    """Decrypt a summed ciphertext with fahe2 decryption scheme."""
    return dec2(decrypt_key, ciph_sum)


def verify_add(msg_sum: int, decrypted_ciph_sum: int):
    """Verify if the decrypted sum of ciphertexts matches the sum of msgs."""
    return msg_sum == decrypted_ciph_sum


def analyze_add(
    index: int, was_successful: bool, msg_sum: int, ciph_sum: int, de_ciph_sum: int
):
    """
    Analyze the result of the addition test and print details.

    Args:
        index (int): Index of the current trial.
        was_successful (bool): Whether the addition was successful.
        msg_sum (int): Sum of messages.
        ciph_sum (int): Sum of ciphertexts.

    Returns:
        None
    """
    global success_number
    if was_successful:
        success_number += 1
        pass_indices.append(index)
        passed_equal_sums.append(msg_sum)
    else:
        fail_indices.append(index)
        failed_msg_sums.append(msg_sum)
        failed_decrypted_ciph_sums.append(de_ciph_sum)

    ciph_length = ciph_sum.bit_length()

    print(
        "\nFAHE1 TEST {}\n"
        "==================\n"
        "alpha                      : {}\n"
        "NUM of additions           : {}\n"
        "M_MAX                      : {}\n"
        "------------------\n"
        "M SUM                      : {}\n"
        "Ciphertext DECRYPT SUM     : {}\n"
        "Was this successful        : {}\n"
        "DECRYPT Ciphertext LENGTH  : {}\n".format(
            index,
            ALPHA,
            NUM_ADDITIONS,
            M_MAX,
            msg_sum,
            fahe1_get_decrypted_sum(ciph_sum),
            was_successful,
            ciph_length,
        )
    )


def add_fahe1(index: int) -> bool:
    """
    Perform the addition test for FAHE1 scheme.

    Args:
        index (int): Index of the current trial.

    Returns:
        was_succesful(bool): Whether the addition was successful.
    """

    # NOTE: You can change msg list params below
    msg_list = populate_message_list(NUM_ADDITIONS)
    ciph_list = fahe1_populate_ciph_list(msg_list)
    msg_sum = get_msg_sum(msg_list)
    ciph_sum = get_ciph_sum(ciph_list)
    de_ciph_sum = fahe1_get_decrypted_sum(ciph_sum)

    was_successful = verify_add(msg_sum, de_ciph_sum)
    analyze_add(index, was_successful, msg_sum, ciph_sum, de_ciph_sum)
    return was_successful


def add_fahe2(index: int) -> bool:
    """
    Perform the addition test for FAHE2 scheme.

    Args:
        index (int): Index of the current trial.

    Returns:
        was_succesful(bool): Whether the addition was successful.
    """

    # NOTE: You can change msg list params below
    msg_list = populate_message_list(NUM_ADDITIONS)
    ciph_list = fahe2_populate_ciph_list(msg_list)
    msg_sum = get_msg_sum(msg_list)
    ciph_sum = get_ciph_sum(ciph_list)
    de_ciph_sum = fahe2_get_decrypted_sum(ciph_sum)

    was_successful = verify_add(msg_sum, de_ciph_sum)
    analyze_add(index, was_successful, msg_sum, ciph_sum, de_ciph_sum)
    return was_successful


def final_analysis():
    """Perform final analysis and display and plot results."""

    print(f"{RED}Failing pairs:{RESET}")
    for i in range(len(fail_indices)):
        print(
            "index = {}, m_total = {}, m_outcome = {}".format(
                fail_indices[i], failed_msg_sums[i], failed_decrypted_ciph_sums[i]
            )
        )

    print(f"\n{GREEN}Successes:{RESET}")
    for i in range(len(passed_equal_sums)):
        print(
            "index = {}, equal_outcome= {}".format(
                pass_indices[i], passed_equal_sums[i]
            )
        )
    print("\nPass rate = {:.2f}%\n".format((success_number) / (NUM_TRIALS) * 100))

    if not fail_indices:
        print(f"{GREEN}COMPLETE SUCCESS! GOOD JOB!\nฅ ^ ≧∇≦^  ฅ\n{RESET}")
    if len(passed_equal_sums) == 0:
        print(f"{RED}COMPLETE FAIL! NO TESTS PASSED\n≽^╥⩊╥^≼\n{RESET}")
    plt.scatter(pass_indices, passed_equal_sums, c="green")
    plt.scatter(fail_indices, failed_msg_sums, c="blue")
    plt.scatter(fail_indices, failed_decrypted_ciph_sums, c="red")
    plt.grid()

    if ENCRYPTION_SCHEME == 1:
        plt.savefig("fahe1add.png")
    else:
        plt.savefig("fahe2add.png")

    plt.show()


def run_add(func):
    """
    Run the addition test for multiple trials.

    Args:
        func: Function argument that determines which encryption scheme to add.
    """
    for trial in range(NUM_TRIALS):
        func(trial)
    final_analysis()


if ENCRYPTION_SCHEME == 1:
    run_add(add_fahe1)
elif ENCRYPTION_SCHEME == 2:
    run_add(add_fahe2)
else:
    print(
        f"\n{RED}Invalid ENCRYPTION_SCHEME value. Please set the value in the code to be either 1 or 2 for FAHE1 or FAHE2 respectively.{RESET}"
    )