from abc import ABC, abstractmethod
from decimal import Decimal
import math
import secrets
from Crypto.Util import number


class FAHE(ABC):
    def __init__(self, lambda_param, m_max, alpha, msg_size, fixed_msg, is_rand_msg):
        self._lambda_param = lambda_param
        self._m_max = m_max
        self._alpha = alpha
        self._msg_size = msg_size
        self._fixed_msg = fixed_msg
        self._is_rand_msg = is_rand_msg

    @property
    def lambda_param(self):
        return self._lambda_param

    @property
    def m_max(self):
        return self._m_max

    @property
    def alpha(self):
        return self._alpha

    @property
    def msg_size(self):
        return self._msg_size

    @msg_size.setter
    def msg_size(self, value):
        self._msg_size = value

    @property
    def fixed_msg(self) -> int:
        return self._fixed_msg

    @fixed_msg.setter
    def fixed_msg(self, value: int):
        self._fixed_msg = value

    @property
    def is_rand_msg(self):
        return self._is_rand_msg

    @is_rand_msg.setter
    def is_rand_msg(self, value: bool):
        self._is_rand_msg = value

    @abstractmethod
    def keygen(self):
        pass

    @abstractmethod
    def enc(self, enc_key, message):
        pass

    @abstractmethod
    def dec(self, dec_key, ciphertext):
        pass


class FAHE1(FAHE):
    encryption_scheme = 1

    def __init__(self, lambda_param, m_max, alpha, msg_size, fixed_msg, is_rand_msg):
        super().__init__(lambda_param, m_max, alpha, msg_size, fixed_msg, is_rand_msg)
        self._full_key = self.keygen()
        self._key = self.full_key[0]
        self._enc_key = self.full_key[1]
        self._dec_key = self.full_key[2]

    def keygen(self):
        rho = self.lambda_param
        eta = rho + (2 * self._alpha) + self._m_max
        gamma = int(rho / math.log2(rho) * ((eta - rho) ** 2))
        p = number.getPrime(eta)
        X = (Decimal(2) ** Decimal(gamma)) / p
        k = (p, self._m_max, X, rho, self._alpha)
        ek = (p, X, rho, self._alpha)
        dk = (p, self._m_max, rho, self._alpha)
        return k, ek, dk

    def enc(self, message):
        p, X, rho, alpha = self._enc_key
        q = secrets.randbelow(int(X + 1))
        noise = secrets.randbits(rho)  # Correct noise generation
        M = (message << (int(rho) + int(alpha))) + noise
        n = p * q
        c = n + M
        return c

    def dec(self, ciphertext) -> int:
        p, m_max, rho, alpha = self._dec_key

        m_full = ciphertext % p
        m_shifted = m_full >> (rho + alpha)

        m_masked = m_shifted & ((1 << m_max) - 1)
        return m_masked
    
    def msg_list_to_ciph_sum(self, msg_list) -> list[int]:
        ciph_list = []
        for _ in msg_list:
            ciph_list.append(self.enc(_))
        return sum(ciph_list)


class FAHE2(FAHE):
    encryption_scheme = 2

    def __init__(self, lambda_param, m_max, alpha, msg_size, fixed_msg, is_rand_msg):
        super().__init__(lambda_param, m_max, alpha, msg_size, fixed_msg, is_rand_msg)
        self._full_key = self.keygen()
        self._key = self.full_key[0]
        self._enc_key = self.full_key[1]
        self._dec_key = self.full_key[2]

    def keygen(self):
        rho = self._lambda_param + self._alpha + self._m_max
        eta = rho + self._alpha
        gamma = int(rho / math.log2(rho) * ((eta - rho) ** 2))
        p = number.getPrime(eta)
        X = (Decimal(2) ** Decimal(gamma)) / p
        pos = secrets.randbelow(
            self._lambda_param + 2
        )  # +2 because lambda is inclusive

        k = (p, X, pos, self._m_max, self._lambda_param, self._alpha)
        ek = (p, X, pos, self._m_max, self._lambda_param, self._alpha)
        dk = (p, pos, self._m_max, self._alpha)
        return k, ek, dk

    def enc(self, message):
        p, X, pos, m_max, lambda_param, alpha = self._enc_key
        q = secrets.randbelow(int(X) + 1)
        noise1 = secrets.randbits(pos)
        noise2 = secrets.randbits(lambda_param - pos)
        M = (noise2 << (pos + m_max + alpha)) + (message << (pos + alpha)) + noise1
        n = p * q
        c = n + M
        return c
    
    def dec(self, ciphertext):
        p, pos, m_max, alpha = self._dec_key

        pos_alpha = int(pos + alpha)
        m_first = (ciphertext % p)
        m_shifted = m_first >> pos_alpha
        m_masked = m_shifted & ((1 << m_max) - 1)

        return m_masked
    
    def msg_list_to_ciph_sum(self, msg_list) -> list[int]:
        ciph_list = []
        for _ in msg_list:
            ciph_list.append(self.enc(_))
        return sum(ciph_list)