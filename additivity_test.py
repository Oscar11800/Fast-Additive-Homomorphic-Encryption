import pytest
from test_additivity2c import run_preset
from test_additivity2c import PresetTests

class TestFAHE1_MINIMUM:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE1_MINIMUM))

class TestFAHE2_MINIMUM:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE2_MINIMUM))

class TestFAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE1_QUANTUM_SMALL_MSG_SMALL_ALPHA))

class TestFAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA))

class TestFAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA))

class TestFAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA))

class TestFAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA))

class TestFAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA))

class TestFAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE1_CLASSICAL_SMALL_MSG_HIGH_ALPHA))

class TestFAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE2_CLASSICAL_SMALL_MSG_HIGH_ALPHA))

class TestFAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE1_QUANTUM_SMALL_MSG_HIGH_ALPHA))

class TestFAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE2_QUANTUM_SMALL_MSG_SMALL_ALPHA))

class TestFAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE1_CLASSICAL_LONG_MSG_SMALL_ALPHA))

class TestFAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE2_CLASSICAL_LONG_MSG_SMALL_ALPHA))

class TestFAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE1_QUANTUM_LONG_MSG_SMALL_ALPHA))

class TestFAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA:
    def test_preset(self):
        print(run_preset(PresetTests.FAHE2_QUANTUM_LONG_MSG_SMALL_ALPHA))

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