import secrets
import unittest
from fahe1 import dec1, enc1, keygen1
from fahe2 import dec2, enc2, keygen2
import time

class TestFAHE1Timed(unittest.TestCase):
    def test_keygen_timed(self):
        """
        Test FAHE1 key generation.
        """
        start_time = time.perf_counter()  # Start timing
        self.m_max = 32
        self.k, self.ek, self.dk = keygen1(128, self.m_max, 6)
        end_time = time.perf_counter()  # End timing
        self.setup_time = end_time - start_time
        print(f"\nFAHE1 key gen time: {self.setup_time:.10f} seconds")
    def test_encrypt_timed(self):
        self.m_max = 32
        self.k, self.ek, self.dk = keygen1(128, self.m_max, 6)
        start_time = time.perf_counter()  # Start timing
        
        m = secrets.randbelow(2**self.m_max - 1)
        c = enc1(self.ek, m)
        
        end_time = time.perf_counter()  # End timing
        self.encode_time = end_time - start_time
        print(f"FAHE1 encode time: {self.encode_time:.10f} seconds")
        
        c_length = c.bit_length()
        print("Length of cyphertext (in bits):", c_length)
        m_outcome = dec1(self.dk, c)
        
class TestFAHE1(unittest.TestCase):
    def setUp(self):
        """
        Setup params for the tests.
        This is also key generation.
        """
        self.m_max = 32
        self.k, self.ek, self.dk = keygen1(128, self.m_max, 6)

    def test_encrypt_decrypt(self):
        """Test the encoding message."""
        m = secrets.randbelow(2**self.m_max - 1)
        print("\nEncoding: ", m)
        c = enc1(self.ek, m)
        c_length = c.bit_length()
        print("Length of cyphertext (in bits):", c_length)
        m_outcome = dec1(self.dk, c)
        print("Decoding: ", m)
        self.assertEqual(m, m_outcome, "Decoded message does not match the original")

    def test_add(self):
        """Test encoding of two messages, their sum, and validate the addition operations. NOTE: alpha should be > than m_max to maintain additivity."""
        m1 = secrets.randbelow(2**self.m_max - 1)
        c1 = enc1(self.ek, m1)
        m2 = secrets.randbelow(2**self.m_max - 1)
        c2 = enc1(self.ek, m2)
        m_sum = m1 + m2
        print("\nEncoding Sum: ", m_sum)
        c_from_m_sum = enc1(self.ek, m_sum)
        c_from_adding = c1 + c2
        m_outcome_from_c_m_sum = dec1(self.dk, c_from_m_sum)
        m_outcome_from_c_adding = dec1(self.dk, c_from_adding)
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


class TestFAHE2(unittest.TestCase):
    def setUp(self):
        """Setup params for the tests."""
        self.m_max = 32
        self.k, self.ek, self.dk = keygen2(128, self.m_max, 6)
        
    def test_keygen(self):
        m_max = 10
        m = secrets.randbelow(2**m_max - 1)
        print("\nEncode: ", m)
        k, ek, dk = keygen2(8, m_max, 10)
        c = enc2(ek, m)
        c_length = c.bit_length()
        print("No. of bits of c:", c_length)
        m_outcome = dec2(dk, c)
        print("Decode: ", m_outcome)

    def test_add(self):
        m_max = 10
        m1 = secrets.randbelow(2**m_max - 1)
        c1 = enc2(self.ek, m1)
        print("Encode m1: ", m1)
        m2 = secrets.randbelow(2**m_max - 1)
        c2 = enc2(self.ek, m2)
        print("Encode m2: ", m2)
        m_sum = m1 + m2
        print("Sum of m, m_sum:", m_sum)
        c_from_m_sum = enc2(self.ek, m_sum)
        c_from_adding = c1 + c2
        m_outcome_from_c_m_sum = dec2(self.dk, c_from_m_sum)
        m_outcome_from_c_adding = dec2(self.dk, c_from_adding)
        print("Decode m_sum from c directly from m_sum: ", m_outcome_from_c_m_sum)
        print("Decode m_sum from c from adding up c1 and c2: ", m_outcome_from_c_adding)


if __name__ == "__main__":
    unittest.main()

# Run this: python -m unittest fahe1.TestFAHE1.test_keygen
