from abc import ABC, abstractmethod
from decimal import Decimal
import math
import secrets
from Crypto.Util import number
import time


class FAHE(ABC):
    def __init__(self, lambda_param, m_max, alpha, msg_size, num_additions):
        self._lambda_param = lambda_param
        self._m_max = m_max
        self._alpha = alpha
        self._msg_size = msg_size
        self._num_additions = num_additions

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
    def num_additions(self) -> int:
        return self._num_additions
    
    @abstractmethod
    def keygen(self):
        pass

    @abstractmethod
    def enc(self, message):
        pass
    
    @abstractmethod
    def enc_list(self, message_list):
        pass

    @abstractmethod
    def dec(self, ciphertext):
        pass


class FAHE1(FAHE):
    encryption_scheme = 1

    def __init__(self, lambda_param, m_max, alpha, msg_size, num_additions):
        super().__init__(lambda_param, m_max, alpha, msg_size, num_additions)
        self._full_key_with_time = self.keygen()
        self._key = self._full_key_with_time[0]
        self._enc_key = self._full_key_with_time[1]
        self._dec_key = self._full_key_with_time[2]
        self._keygen_time = self._full_key_with_time[3]

    @property
    def keygen_time(self):
        return self._keygen_time

    def keygen(self):
        tik = time.time()
        rho = self.lambda_param
        eta = rho + (2 * self._alpha) + self._m_max
        gamma = int(rho / math.log2(rho) * ((eta - rho) ** 2))
        p = number.getPrime(eta)
        X = (Decimal(2) ** Decimal(gamma)) / p
        k = (p, self._m_max, X, rho, self._alpha)
        tok = time.time()
        ek = (p, X, rho, self._alpha)
        dk = (p, self._m_max, rho, self._alpha)
        return k, ek, dk, tok - tik

    def enc(self, message):
        tik = time.time()
        p, X, rho, alpha = self._enc_key
        q = secrets.randbelow(int(X + 1))
        noise = secrets.randbits(rho)  # Correct noise generation
        M = (message << (int(rho) + int(alpha))) + noise
        n = p * q
        c = n + M
        tok = time.time()
        return c, tok - tik
    
    def enc_list(self, message_list):
        c_list = []
        t_list = []
        for _ in message_list:
            c, t = self.enc(_)
            c_list.append(c)
            t_list.append(t)
        return c_list, t_list
    
    def dec_list(self, ciph_list):
        msg_list = []
        t_list = []
        for c in ciph_list:
            m_masked, t = self.dec(c)
            msg_list.append(m_masked)
            t_list.append(t)
        return msg_list, t_list
            

    def dec(self, ciphertext) -> int:
        tik = time.time()
        p, m_max, rho, alpha = self._dec_key

        m_full = ciphertext % p
        m_shifted = m_full >> (rho + alpha)

        m_masked = m_shifted & ((1 << m_max) - 1)
        tok = time.time()
        return m_masked, tok - tik


class FAHE2(FAHE):
    encryption_scheme = 2

    def __init__(self, lambda_param, m_max, alpha, msg_size, num_additions):
        super().__init__(lambda_param, m_max, alpha, msg_size, num_additions)
        self._full_key_with_time = self.keygen()
        self._key = self._full_key_with_time[0]
        self._enc_key = self._full_key_with_time[1]
        self._dec_key = self._full_key_with_time[2]
        self._keygen_time = self._full_key_with_time[3]

    @property
    def keygen_time(self):
        return self._keygen_time

    def keygen(self):
        tik = time.time()
        rho = self._lambda_param + self._alpha + self._m_max
        eta = rho + self._alpha
        gamma = int(rho / math.log2(rho) * ((eta - rho) ** 2))
        p = number.getPrime(eta)
        X = (Decimal(2) ** Decimal(gamma)) / p
        pos = secrets.randbelow(
            self._lambda_param + 2
        )  # +2 because lambda is inclusive

        k = (p, X, pos, self._m_max, self._lambda_param, self._alpha)
        tok = time.time()
        ek = (p, X, pos, self._m_max, self._lambda_param, self._alpha)
        dk = (p, pos, self._m_max, self._alpha)
        return k, ek, dk, tok - tik

    def enc(self, message):
        tik = time.time()
        p, X, pos, m_max, lambda_param, alpha = self._enc_key
        q = secrets.randbelow(int(X) + 1)
        noise1 = secrets.randbits(pos)
        noise2 = secrets.randbits(lambda_param - pos)
        M = (noise2 << (pos + m_max + alpha)) + (message << (pos + alpha)) + noise1
        n = p * q
        c = n + M
        tok = time.time()
        return c, tok - tik
    
    def enc_list(self, message_list):
        c_list = []
        t_list = []
        for _ in message_list:
            c, t = self.enc(_)
            c_list.append(c)
            t_list.append(t)
        return c_list, t_list
            
    def dec(self, ciphertext):
        tik = time.time()
        p, pos, m_max, alpha = self._dec_key

        pos_alpha = int(pos + alpha)
        m_first = (ciphertext % p)
        m_shifted = m_first >> pos_alpha
        m_masked = m_shifted & ((1 << m_max) - 1)
        tok = time.time()

        return m_masked, tok - tik
    
    def dec_list(self, ciph_list):
        msg_list = []
        t_list = []
        for c in ciph_list:
            m_masked, t = self.dec(c)
            msg_list.append(m_masked)
            t_list.append(t)
        return msg_list, t_list