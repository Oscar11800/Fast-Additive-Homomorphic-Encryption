import secrets
import unittest
from legacy.data_collection import Operation, collect_security_param_performance, get_op_func_map, print_data_points, collect_security_param_ciphertext, collect_alpha_performance
from fahe1 import dec1, enc1, length_enc1, keygen1
from fahe2 import dec2, enc2, keygen2
import time
from plotting import plot_performance, plot_ciphertext_size

class TestFAHE1GraphKeyGenLambdaPerformance(unittest.TestCase):
    def setUp(self) -> None:
        self.operation_map = get_op_func_map()
        
    def test_data_collection_timed_keygen1(self):
        params = {
            'm_max': 32,
            'alpha': 6,
            'm': 'example message',

        }

        data_points = collect_security_param_performance(2, 100, 2, Operation.TIMED_KEYGEN, self.operation_map, params)
        print_data_points(data_points)
        plot_performance(data_points, 'Key Generation Time Performance vs. Lambda', 'Lambda', 'Time Performance (millisec)')

class TestFAHE1GraphKeyGenAlphaPerformance(unittest.TestCase):
    def setUp(self) -> None:
        self.operation_map = get_op_func_map()
        
    def test_data_collection_timed_keygen1(self):
        params = {
            'lambda': 32,
            'm_max': 32,
            'm': 'example message',

        }
        data_points = collect_alpha_performance(2, 100, 2, Operation.TIMED_KEYGEN, self.operation_map, params)
        print_data_points(data_points)
        plot_performance(data_points, 'Key Generation Time Performance vs. Alpha', 'Alpha', 'Time Performance (millisec)')
        
class TestFAHE1GraphKeyGenMMAxPerformance(unittest.TestCase):
    def setUp(self) -> None:
        self.operation_map = get_op_func_map()
        
    def test_data_collection_timed_keygen1(self):
        params = {
            'lambda': 32,
            'alpha': 6,
            'm': 'example message',
        }
        data_points = collect_alpha_performance(2, 100, 2, Operation.TIMED_KEYGEN, self.operation_map, params)
        print_data_points(data_points)
        plot_performance(data_points, 'Key Generation Time Performance vs. Alpha', 'Alpha', 'Time Performance (millisec)')


class TestFAHE1GraphEncryptLambdaPerformance(unittest.TestCase):
    def setUp(self) -> None:
        self.operation_map = get_op_func_map()
        self.m_max = 32
        
    def test_data_collection_timed_encrypt_(self):
        params = {
            'm_max': self.m_max,
            'alpha': 6,
            'm': secrets.randbelow(2**self.m_max - 1),
        }
        
        data_points = collect_security_param_performance(64, 256, 8, Operation.TIMED_ENCODE, self.operation_map, params)
        print_data_points(data_points)
        plot_performance(data_points, 'Encrypt Time Performance vs. Lambda', 'Lambda', 'Time Performance (millisec)')
        
class TestFAHE1GraphEncryptLambdaCiphertext(unittest.TestCase):
    def setUp(self) -> None:
        self.m_max = 32
        
    def test_data_collection_ciphertext(self):
        params = {
            'm_max': self.m_max,
            'alpha': 6,
            'm': secrets.randbelow(2**self.m_max - 1),
        }
        
        data_points = collect_security_param_ciphertext(2, 1000, 8, params)
        print_data_points(data_points)
        plot_ciphertext_size(data_points, 'Encrypt Ciphertext Size vs. Lambda', 'Lambda', 'Ciphertext Size')
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
        print("Length of ciphertext (in bits):", c_length)
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
        print("Length of ciphertext (in bits):", c_length)
        m_outcome = dec1(self.dk, c)
        print("Decoding: ", m)
        self.assertEqual(m, m_outcome, "Decoded message does not match the original")

    def test_add(self):
        """Test encoding of two messages, their sum, and validate the addition operations."""
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

if __name__ == "__main__":
    unittest.main()

# Run this: python -m unittest fahe1.TestFAHE1.test_keygen
