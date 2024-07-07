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


@pytest.fixture
def fahe1(request) -> "FAHE1":
    """Fixture to initialize FAHE1 with dynamic parameters."""
    if GLOBAL_CUSTOM_PARAMS:
        lambda_param, m_max, alpha, msg_size, num_additions = request
    else:
        if len(request.param) == 5:
            lambda_param, m_max, alpha, msg_size, num_additions = request
        else:
            match(request[0]):
                case PresetTests.FAHE1_MINIMUM:
                    lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_MINIMUM
                case PresetTests.FAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA:
                    lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA
                case PresetTests.FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA:
                    lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA
                case PresetTests.FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA:
                    lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA
                case PresetTests.FAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA:
                    lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA
                case PresetTests.FAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA:
                    lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA
                case PresetTests.FAHE1_CLASSICAL_LONG_MSG_HIGH_ALPHA:
                    lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_CLASSICAL_LONG_MSG_HIGH_ALPHA
                case PresetTests.FAHE1_QUANTUM_LONG_MSG_HIGH_ALPHA:
                    lambda_param, m_max, alpha, msg_size = PresetTests.FAHE1_QUANTUM_LONG_MSG_HIGH_ALPHA
                case _:
                    lambda_param, m_max, alpha, msg_size, num_additions = request
        num_additions = alpha
        
        
    return FAHE1(lambda_param, m_max, alpha, msg_size, num_additions)

@pytest.fixture
def fahe2(request) -> "FAHE2":
    """Fixture to initialize FAHE2 with dynamic parameters."""
    if GLOBAL_CUSTOM_PARAMS:
        lambda_param, m_max, alpha, msg_size, num_additions = request
    else:
        match(request[0]):
            case PresetTests.FAHE2_MINIMUM:
                lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_MINIMUM
            case PresetTests.FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA:
                lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA
            case PresetTests.FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA:
                lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA
            case PresetTests.FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA:
                lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA
            case PresetTests.FAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA:
                lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA
            case PresetTests.FAHE2_QUANTUM_SMALL_MSG_HIGH_ALPHA:
                lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_QUANTUM_SMALL_MSG_HIGH_ALPHA
            case PresetTests.FAHE2_CLASSICAL_LONG_MSG_HIGH_ALPHA:
                lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_CLASSICAL_LONG_MSG_HIGH_ALPHA
            case PresetTests.FAHE2_QUANTUM_LONG_MSG_HIGH_ALPHA:
                lambda_param, m_max, alpha, msg_size = PresetTests.FAHE2_QUANTUM_LONG_MSG_HIGH_ALPHA
            case _:
                    lambda_param, m_max, alpha, msg_size, num_additions = request
        num_additions = alpha
        
    return FAHE2(lambda_param, m_max, alpha, msg_size, num_additions)

class TestHelper:
    def generate_msg_list(self, num_msgs, msg_size: int)-> list[int]:
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
    
    def get_msg_sum(self, msg_list: list[int]) ->int:
        """Calculate the direct sum of a list of messages."""
        return sum(msg_list)

    def get_masked_msg_sum(self, msg_sum: int, m_max:int) -> int:
        return msg_sum & ((1 << m_max) - 1)
    
    # TODO: FIX THIS METHOD (add_fahe) SO THAT ALL TESTS CAN LOOK LIKE test_fahe1_minimum
    # def add_fahe(self, index: int, fahe: FAHE) -> bool:
    #     """
    #     Perform the addition test for FAHE scheme.

    #     Args:
    #         index (int): Index of the current trial.

    #     Returns:
    #         was_succesful(bool): Whether the addition was successful.
    #     """

    #     # NOTE: You can change msg list params below
    #     msg_list = self.generate_msg_list()
    #     ciph_list = fahe2_populate_ciph_list(msg_list)
    #     msg_sum = get_msg_sum(msg_list)
    #     masked_msg_sum = get_masked_msg_sum(msg_sum)
    #     ciph_sum = get_ciph_sum(ciph_list)
    #     de_ciph_sum = fahe2_get_decrypted_sum(ciph_sum)

    #     was_successful = verify_add(masked_msg_sum, de_ciph_sum)
    #     analyze_add(index, was_successful, masked_msg_sum, ciph_sum, de_ciph_sum)
    #     return was_successful
        
class TestFAHE1:
    @pytest.mark.parametrize(
        "fahe1", "preset_test",[(PresetTests.FAHE1_MINIMUM)],indirect=["fahe1"],
    )
    def test_fahe1_minimum(self, fahe1: FAHE1, preset_test: PresetTests):
        assert TestHelper.add_fahe(fahe1)