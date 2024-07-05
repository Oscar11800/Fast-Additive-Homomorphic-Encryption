import pytest
from test_additivity2c import run_preset
from test_additivity2c import PresetTests

class TestHelper():
    def populate_message_list(
    num_msgs: int, msg: int = random.getrandbits(MSG_SIZE)):
        """
        Populate a list of random messages.

        Args:
            num_msgs (int): Number of messages to generate.
            # is_single_msg (bool): Whether to use a single message for all entries.
            msg (int): A specific message to use if is_single_msg is True.

        Returns:
            list[int]: List of generated messages.
        """
        if IS_RAND_MSG:
            return [random.getrandbits(MSG_SIZE) for _ in range(num_msgs)]
        else:
            return [msg] * num_msgs


class TestFAHE1_MINIMUM:
    def test_preset(self):
        run_preset(PresetTests.FAHE1_MINIMUM)

class TestFAHE2_MINIMUM:
    def test_preset(self):
        run_preset(PresetTests.FAHE2_MINIMUM)

class TestFAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA)

class TestFAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA)

class TestFAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA)

class TestFAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA)

class TestFAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA)

class TestFAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA)

class TestFAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA)

class TestFAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA)

class TestFAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA)

class TestFAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA)

class TestFAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA)

class TestFAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA)

class TestFAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA)

class TestFAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        run_preset(PresetTests.FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA)

# To test the functions
if __name__ == "__main__":
    TestFAHE1_MINIMUM().test_preset()
    TestFAHE2_MINIMUM().test_preset()
    TestFAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA().test_preset()
    TestFAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA().test_preset()
    TestFAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA().test_preset()
    TestFAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA().test_preset()
    TestFAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA().test_preset()
    TestFAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA().test_preset()
    TestFAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA().test_preset()
    TestFAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA().test_preset()
    TestFAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA().test_preset()
    TestFAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA().test_preset()
    TestFAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA().test_preset()
    TestFAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA().test_preset()
    TestFAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA().test_preset()
    TestFAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA().test_preset()