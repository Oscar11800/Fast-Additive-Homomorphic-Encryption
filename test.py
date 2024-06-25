import secrets
import unittest
from fahe1 import dec, enc, keygen


class TestFAHE1(unittest.TestCase):
    def setUp(self):
        """Setup params for the tests."""
        self.m_max = 32
        self.k, self.ek, self.dk = keygen(128, self.m_max, 6)

    def test_keygen(self):
        """Test the key gen, encode, and decoding of a message."""
        m = secrets.randbelow(2**self.m_max - 1)
        print("\nEncoding: ", m)
        c = enc(self.ek, m)
        m_outcome = dec(self.dk, c)
        print("Decoding: ", m)
        self.assertEqual(m, m_outcome, "Decoded message does not match the original")

    def test_add(self):
        """Test encoding of two messages, their sum, and validate the addition operations. NOTE: alpha should be > than m_max to maintain additivity."""
        m1 = secrets.randbelow(2**self.m_max - 1)
        c1 = enc(self.ek, m1)
        m2 = secrets.randbelow(2**self.m_max - 1)
        c2 = enc(self.ek, m2)
        m_sum = m1 + m2
        print("\nEncoding Sum: ", m_sum)
        c_from_m_sum = enc(self.ek, m_sum)
        c_from_adding = c1 + c2
        m_outcome_from_c_m_sum = dec(self.dk, c_from_m_sum)
        m_outcome_from_c_adding = dec(self.dk, c_from_adding)
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


if __name__ == "__main__":
    unittest.main()

# Run this: python -m unittest fahe1.TestFAHE1.test_keygen
