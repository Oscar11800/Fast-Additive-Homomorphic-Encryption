from enum import Enum
import random
import pytest
from test_additivity2c import run_preset
from test_additivity2c import PresetTests
from fahe import FAHE, FAHE1
from fahe import FAHE2

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
    FAHE1_MINIMUM = (128, 32, 6, 32, 2**5)
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
        msg_list = TestHelper.generate_msg_list(NUM_TRIALS, fahe.msg_size)
        ciph_list = fahe.enc_list(msg_list)
        msg_sum = TestHelper.get_msg_sum(msg_list)
        masked_msg_sum = TestHelper.get_masked_msg_sum(msg_sum, fahe.m_max)
        ciph_sum = TestHelper.get_ciph_sum(ciph_list)
        de_ciph_sum = fahe.dec(ciph_sum)

        was_successful = TestHelper.verify_add(masked_msg_sum, de_ciph_sum)
        return was_successful
        
class TestFAHE1:
    @pytest.mark.parametrize("fahe1", [PresetTests.FAHE1_MINIMUM], indirect=True)
    def test_fahe1_minimum(self, fahe1: "FAHE1"):
        TestHelper.fahe_debug(fahe1)
        assert TestHelper.add_fahe(fahe1)