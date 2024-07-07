from enum import Enum
import pytest
from test_additivity2c import run_preset
from test_additivity2c import PresetTests
from fahe import FAHE1
from fahe import FAHE2

TOGGLE_CUSTOM_PARAMS = False    # turn this on to test CUSTOM_PARAMS
NUM_TRIALS = 6  # number of trials to run each test

CUSTOM_PARAMS = (
    256,    #lambda
    64, #m_max
    33, #alpha
    64, #msg_size (usually m_max)
    1000, #num additions, usually 2**(alpha-1)
    2,  #encryption scheme
    False,  #is_set_msg
    2364110189  #optional: set msg
)

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
    if TOGGLE_CUSTOM_PARAMS:
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
        
    return FAHE1(lambda_param, m_max, alpha, msg_size, num_additions)

@pytest.fixture
def fahe2(request) -> "FAHE2":
    """Fixture to initialize FAHE2 with dynamic parameters."""
    if TOGGLE_CUSTOM_PARAMS:
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
        
    return FAHE2(lambda_param, m_max, alpha, msg_size, num_additions)

class TestFAHE1:
    

































# class TestHelper():
#     def populate_message_list(
#     num_msgs: int, msg: int = random.getrandbits(MSG_SIZE)):
#         """
#         Populate a list of random messages.

#         Args:
#             num_msgs (int): Number of messages to generate.
#             # is_single_msg (bool): Whether to use a single message for all entries.
#             msg (int): A specific message to use if is_single_msg is True.

#         Returns:
#             list[int]: List of generated messages.
#         """
#         if IS_RAND_MSG:
#             return [random.getrandbits(MSG_SIZE) for _ in range(num_msgs)]
#         else:
#             return [msg] * num_msgs


# class TestFAHE1_MINIMUM:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE1_MINIMUM)

# class TestFAHE2_MINIMUM:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE2_MINIMUM)

# class TestFAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA)

# class TestFAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA)

# class TestFAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA)

# class TestFAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA)

# class TestFAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA)

# class TestFAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA)

# class TestFAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA)

# class TestFAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA)

# class TestFAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA)

# class TestFAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA)

# class TestFAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA)

# class TestFAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA)

# class TestFAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA)

# class TestFAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA:
#     def test_preset(self):
#         run_preset(PresetTests.FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA)

# # To test the functions
# if __name__ == "__main__":
#     TestFAHE1_MINIMUM().test_preset()
#     TestFAHE2_MINIMUM().test_preset()
#     TestFAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA().test_preset()
#     TestFAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA().test_preset()
#     TestFAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA().test_preset()
#     TestFAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA().test_preset()
#     TestFAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA().test_preset()
#     TestFAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA().test_preset()
#     TestFAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA().test_preset()
#     TestFAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA().test_preset()
#     TestFAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA().test_preset()
#     TestFAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA().test_preset()
#     TestFAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA().test_preset()
#     TestFAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA().test_preset()
#     TestFAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA().test_preset()
#     TestFAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA().test_preset()