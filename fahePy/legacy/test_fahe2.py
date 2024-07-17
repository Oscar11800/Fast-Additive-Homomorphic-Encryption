import secrets
import unittest
from legacy.data_collection import (
    Operation,
    collect_security_param_performance,
    get_op_func_map,
    print_data_points,
    collect_security_param_ciphertext,
    collect_alpha_performance,
)
from fahe1 import dec1, length_enc1, keygen1
from fahe2 import dec2, enc2, keygen2
import time
from plotting import plot_performance, plot_ciphertext_size


class TestFAHE2(unittest.TestCase):
    def setUp(self):
        """Setup params for the tests."""
        self.m_max = 32
        self.k, self.ek, self.dk = keygen2(128, self.m_max, 128)

    # def test_keygen(self):
    #     m = secrets.randbelow(2**self.m_max)
    #     print("\nEncoding: ", m)
    #     c = enc2(self.ek, m)
    #     c_length = c.bit_length()
    #     print("Length of ciphertext (in bits):", c_length)
    #     m_outcome = dec2(self.dk, c)
    #     print("Decoding: ", m_outcome)
    #     self.assertEqual(m, m_outcome, "Decoded message does not match the original")

    def test_add(self):
        """Test encoding of two messages, their sum, and validate the addition operations. NOTE: alpha should be > than m_max to maintain additivity."""
        m1 = secrets.randbelow(2**self.m_max)
        c1 = enc2(self.ek, m1)
        m2 = secrets.randbelow(2**self.m_max)
        c2 = enc2(self.ek, m2)
        m_sum = m1 + m2
        print("\nEncoding Sum: ", m_sum)
        c_from_m_sum = enc2(self.ek, m_sum)
        c_from_adding = c1 + c2
        m_outcome_from_c_m_sum = dec2(self.dk, c_from_m_sum)
        m_outcome_from_c_adding = dec2(self.dk, c_from_adding)
        print("Decoding Sum: ", m_outcome_from_c_m_sum)
        print("Direct Sum: ", m_outcome_from_c_adding)
        self.assertEqual(
            m_sum,
            m_outcome_from_c_m_sum,
            "Decoded sum does not match the actual sum from encoded messages",
        )
        self.assertEqual(
            m_outcome_from_c_m_sum,
            m_outcome_from_c_adding,
            "Direct sum and encoded sum results differ",
        )
