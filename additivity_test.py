from enum import Enum
import random
import pytest
from test_additivity2c import run_preset
from test_additivity2c import PresetTests
from fahe import FAHE, FAHE1
from fahe import FAHE2
import matplotlib.pyplot as plt

# Printing values
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"


GLOBAL_CUSTOM_PARAMS = False    # Runs all tests with custom params
CUSTOM_PARAMS = (
    256,    #lambda
    64, #m_max
    33, #alpha
    64, #msg_size (usually m_max)
    1000, #num additions, usually 2**(alpha-1)
)

# The following constants are for preset tests and custom tests
NUM_TRIALS = 6  # number of trials to run each test
TOGGLE_FIXED_MESSAGE = False
FIXED_MESSAGE = 2364110189



class PresetTests(Enum):
    # TESTx = (
    #   LAMBDA_PARAM,
    #   M_MAX,
    #   ALPHA,
    #   NUM_ADDITIONS,
    #   NUM_TRIALS,
    #   MSG_SIZE,
    #   ENCRYPTION_SCHEME,
    #   SET_MSG,
    #   IS_RAND_MSG)
    FAHE1_MINIMUM = (128, 32, 6, 10, 21, 28, 1, 2364110189)
    FAHE2_MINIMUM = (128, 32, 29, 10, 21, 28, 2, 2364110189)
    FAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA = (256, 32, 6, 10, 21, 28, 1, 2364110189)
    FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA = (256, 32, 22, 10, 21, 28, 2, 2364110189)
    FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA = (128, 64, 6, 10, 21, 28, 1, 2364110189)
    FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA = (128, 64, 29, 10, 21, 28, 2, 2364110189)
    FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA = (256, 64, 6, 10, 21, 28, 1, 2364110189)
    FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA = (256, 64, 21, 10, 21, 28, 2, 2364110189)
    FAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA = (128, 32, 33, 10, 21, 28, 1, 2364110189)
    FAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA = (128, 32, 33, 10, 21, 28, 2, 2364110189)
    FAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA = (256, 32, 33, 10, 21, 28, 1, 2364110189)
    FAHE2_QUANTUM_SMALL_MSG_HIGH_ALPHA = (256, 32, 33, 10, 21, 28, 2, 2364110189)
    FAHE1_CLASSICAL_LONG_MSG_HIGH_ALPHA = (128, 64, 33, 10, 21, 28, 1, 2364110189)
    FAHE2_CLASSICAL_LONG_MSG_HIGH_ALPHA = (128, 64, 33, 10, 21, 28, 2, 2364110189)
    FAHE1_QUANTUM_LONG_MSG_HIGH_ALPHA = (256, 64, 33, 10, 21, 28, 1, 2364110189)
    FAHE2_QUANTUM_LONG_MSG_HIGH_ALPHA = (256, 64, 33, 10, 21, 28, 2, 2364110189)


# @pytest.fixture
# def fahe1(request) -> "FAHE1":
#     """Fixture to initialize FAHE1 with dynamic parameters."""
#     if GLOBAL_CUSTOM_PARAMS:
#         lambda_param, m_max, alpha, msg_size, num_additions = request
#     else:
#         if len(request.param) == 5:
#             lambda_param, m_max, alpha, msg_size, num_additions = request
#         else:
#             match(request[0]):
#                 case PresetTests.FAHE1_MINIMUM:
#                     lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_MINIMUM
#                 case PresetTests.FAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA:
#                     lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA
#                 case PresetTests.FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA:
#                     lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA
#                 case PresetTests.FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA:
#                     lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA
#                 case PresetTests.FAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA:
#                     lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA
#                 case PresetTests.FAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA:
#                     lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA
#                 case PresetTests.FAHE1_CLASSICAL_LONG_MSG_HIGH_ALPHA:
#                     lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_CLASSICAL_LONG_MSG_HIGH_ALPHA
#                 case PresetTests.FAHE1_QUANTUM_LONG_MSG_HIGH_ALPHA:
#                     lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_QUANTUM_LONG_MSG_HIGH_ALPHA
#                 case _:
#                     lambda_param, m_max, alpha, msg_size, num_additions = request
#         num_additions = alpha
        
        
#     return FAHE1(lambda_param, m_max, alpha, msg_size, num_additions)

# @pytest.fixture
# def fahe2(request) -> "FAHE2":
#     """Fixture to initialize FAHE2 with dynamic parameters."""
#     if GLOBAL_CUSTOM_PARAMS:
#         lambda_param, m_max, alpha, msg_size, num_additions = request
#     else:
#         match(request[0]):
#             case PresetTests.FAHE2_MINIMUM:
#                 lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_MINIMUM
#             case PresetTests.FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA:
#                 lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA
#             case PresetTests.FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA:
#                 lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA
#             case PresetTests.FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA:
#                 lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA
#             case PresetTests.FAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA:
#                 lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA
#             case PresetTests.FAHE2_QUANTUM_SMALL_MSG_HIGH_ALPHA:
#                 lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_QUANTUM_SMALL_MSG_HIGH_ALPHA
#             case PresetTests.FAHE2_CLASSICAL_LONG_MSG_HIGH_ALPHA:
#                 lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_CLASSICAL_LONG_MSG_HIGH_ALPHA
#             case PresetTests.FAHE2_QUANTUM_LONG_MSG_HIGH_ALPHA:
#                 lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_QUANTUM_LONG_MSG_HIGH_ALPHA
#             case _:
#                     lambda_param, m_max, alpha, msg_size, num_additions = request
#         num_additions = alpha
        
#     return FAHE2(lambda_param, m_max, alpha, msg_size, num_additions)

@pytest.fixture
def fahe1(request) -> "FAHE1":
    """Fixture to initialize FAHE1 with dynamic parameters."""
    if GLOBAL_CUSTOM_PARAMS:
        lambda_param, m_max, alpha, msg_size, num_additions = CUSTOM_PARAMS
    else:
        preset = request.param
        lambda_param, m_max, alpha, msg_size, num_additions = preset.value[:5]
    
    return FAHE1(lambda_param, m_max, alpha, msg_size, num_additions)

@pytest.fixture
def fahe2(request) -> "FAHE2":
    """Fixture to initialize FAHE2 with dynamic parameters."""
    if GLOBAL_CUSTOM_PARAMS:
        lambda_param, m_max, alpha, msg_size, num_additions = CUSTOM_PARAMS
    else:
        preset = request.param
        lambda_param, m_max, alpha, msg_size, num_additions = preset.value[:5]
    
    return FAHE2(lambda_param, m_max, alpha, msg_size, num_additions)
class TestHelper:
    @staticmethod
    def generate_msg_list(num_msgs, msg_size: int)-> list[int]:
        """
        Populate a list of random messages.

        Args:
            num_msgs (int): Number of messages to generate.
            msg_side (int): Size of each message in bits

        Returns:
            list[int]: List of generated messages.
        """
        if TOGGLE_FIXED_MESSAGE:
            return [FIXED_MESSAGE] * num_msgs
        else:
            return [random.getrandbits(msg_size) for _ in range(num_msgs)]
    
    @staticmethod
    def get_msg_sum(msg_list: list[int]) ->int:
        """Calculate the direct sum of a list of messages."""
        return sum(msg_list)

    @staticmethod
    def get_masked_msg_sum(msg_sum: int, m_max:int) -> int:
        return msg_sum & ((1 << m_max) - 1)
    
    @staticmethod
    def get_ciph_sum(c_list: list[int]):
        """Calculate the sum of a list of ciphertexts."""
        return sum(c_list)
    
    @staticmethod
    def verify_add(masked_msg_sum: int, decrypted_ciph_sum: int):
        """Verify if the decrypted sum of ciphertexts matches the sum of msgs."""
        return masked_msg_sum == decrypted_ciph_sum
        
    @staticmethod
    def fahe_debug(fahe: "FAHE"):
        if isinstance(fahe, FAHE1):
            print("IS FAHE1")
        elif isinstance(fahe, FAHE2):
            print("IS FAHE2")
        else:
            print("SCHEME TYPE ERROR!")

        print("lambda_param: ", fahe.lambda_param)
        print("m_max: ", fahe.m_max)
        print("alpha: ", fahe.alpha)
        print("num_additions: ", fahe.num_additions)
    
    @staticmethod
    def add_fahe(fahe: FAHE) -> bool:
        """
        Perform the addition test for FAHE scheme.

        Args:
            index (int): Index of the current trial.

        Returns:
            was_succesful(bool): Whether the addition was successful.
        """

        # NOTE: You can change msg list params below
        msg_list = TestHelper.generate_msg_list(fahe.num_additions, fahe.msg_size)
        ciph_list = fahe.enc_list(msg_list)
        msg_sum = TestHelper.get_msg_sum(msg_list)
        masked_msg_sum = TestHelper.get_masked_msg_sum(msg_sum, fahe.m_max)
        ciph_sum = TestHelper.get_ciph_sum(ciph_list)
        de_ciph_sum = fahe.dec(ciph_sum)

        was_successful = TestHelper.verify_add(masked_msg_sum, de_ciph_sum)
        return was_successful, masked_msg_sum, de_ciph_sum
    
    @staticmethod
    def run_add(fahe: FAHE):
        num_successes = 0 
        pass_indices = []
        fail_indices = []
        pass_equal_sums = []
        failed_msg_sums = []
        failed_decrypted_ciph_sums = []


        for trial in range(NUM_TRIALS):
            msg_list = TestHelper.generate_msg_list(fahe.num_additions, fahe.msg_size)
            ciph_list = fahe.enc_list(msg_list)
            msg_sum = TestHelper.get_msg_sum(msg_list)
            masked_msg_sum = TestHelper.get_masked_msg_sum(msg_sum, fahe.m_max)
            ciph_sum = TestHelper.get_ciph_sum(ciph_list)
            de_ciph_sum = fahe.dec(ciph_sum)
            
            was_successful = TestHelper.verify_add(masked_msg_sum, de_ciph_sum)
            
            if was_successful:
                pass_indices.append(trial)
                pass_equal_sums.append(msg_sum)
                num_successes += 1
            else:
                fail_indices.append(trial)
                failed_msg_sums.append(msg_sum)
                failed_decrypted_ciph_sums.append(de_ciph_sum)

            ciph_length = ciph_sum.bit_length()

            print(
            "\nFAHE Test {}\n"
            "==================\n"
            "alpha                      : {}\n"
            "NUM of additions           : {}\n"
            "M_MAX                      : {}\n"
            "------------------\n"
            "M SUM                      : {}\n"
            "Bit length of M SUM        : {}\n"
            # "Ciphertext DECRYPT SUM     : {}\n"
            # "Bit length of Decrypted sum: {}\n"
            "Was this successful        : {}\n"
            "DECRYPT Ciphertext LENGTH  : {}\n".format(
                # ENCRYPTION_SCHEME,
                trial,
                fahe.alpha,
                fahe.num_additions,
                fahe.m_max,
                bin(msg_sum),
                msg_sum.bit_length(),
                # (
                #     bin(fahe1_get_decrypted_sum(ciph_sum))
                #     if ENCRYPTION_SCHEME == 1
                #     else bin(fahe2_get_decrypted_sum(ciph_sum))
                # ),
                # (
                #     fahe1_get_decrypted_sum(ciph_sum).bit_length()
                #     if ENCRYPTION_SCHEME == 1
                #     else fahe2_get_decrypted_sum(ciph_sum).bit_length()
                # ),
                was_successful,
                ciph_length,
                )
            )
        
        TestHelper.final_analysis(
            (pass_indices, 
             pass_equal_sums, 
             fail_indices, 
             failed_msg_sums, 
             failed_decrypted_ciph_sums,
             num_successes)
        )
        return num_successes == NUM_TRIALS

    
    @staticmethod
    def final_analysis(tuple_of_lists_for_analysis):
        pass_indices, pass_equal_sums, fail_indices, failed_msg_sums, failed_decrypted_ciph_sums, num_successes = tuple_of_lists_for_analysis
        
        """Perform final analysis and display and plot results."""

        print(f"{RED}Failing pairs:{RESET}")
        for i in range(len(fail_indices)):
            print(
                "index = {}, msg_sum = {}, decrypted_sum = {}".format(
                    fail_indices[i], failed_msg_sums[i], failed_decrypted_ciph_sums[i]
                )
            )

        print(f"\n{GREEN}Successes:{RESET}")
        for i in range(len(pass_equal_sums)):
            print(
                "index = {}, equal_outcome= {}".format(
                    pass_indices[i], pass_equal_sums[i]
                )
            )
        print("\nPass rate = {:.2f}%\n".format((num_successes) / (NUM_TRIALS) * 100))

        if not fail_indices:
            print(f"{GREEN}COMPLETE SUCCESS! GOOD JOB!\nฅ ^ ≧∇≦^  ฅ\n{RESET}")
        if len(pass_equal_sums) == 0:
            print(f"{RED}COMPLETE FAIL! NO TESTS PASSED\n≽^╥⩊╥^≼\n{RESET}")
        plt.scatter(pass_indices, pass_equal_sums, c="green")
        plt.scatter(fail_indices, failed_msg_sums, c="blue")
        plt.scatter(fail_indices, failed_decrypted_ciph_sums, c="red")
        plt.grid()

        # if ENCRYPTION_SCHEME == 1:
        #     plt.savefig("graphs/fahe1add.png")
        # else:
        #     plt.savefig("graphs/fahe2add.png")
            
        # with warnings.catch_warnings():
        #     warnings.simplefilter("ignore", category=UserWarning)
        #     plt.show()

class TestFAHE1:
    @pytest.mark.parametrize("fahe1", [PresetTests.FAHE1_MINIMUM], indirect=True)
    def test_fahe1_minimum(self, fahe1: "FAHE1"):
        TestHelper.fahe_debug(fahe1)
        assert TestHelper.run_add(fahe1)