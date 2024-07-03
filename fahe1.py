from decimal import Decimal
import math
import secrets
import sys
import time
import helper
import random
from typing import Tuple

#  Cominetti, Eduardo & Simplicio, Marcos. (2020). Fast Additive Partially Homomorphic Encryption From the Approximate Common Divisor Problem. IEEE Transactions on Information Forensics and Security. PP. 1-1. 10.1109/TIFS.2020.2981239.


def keygen1(l, m_max, alpha) -> tuple[float]:
    """
    Generates a FAHE1 key.
    There is random process within this function (large prime p is random)
    
    rho: noise parameter
    eta: secret key size
    gamma: final ciphertext max size

    Args:
        l: security parameter (lambda)
        m_max: maximum message size (int bits)
        alpha: total number of supported additions
        p: a prime number of eta size bits

    Returns:
        k, ek, dk: tuple of [scheme key, encrypt key, decrypt key] respectively
    """

    rho = l
    eta = rho + (2 * alpha) + m_max
    gamma = int(rho / math.log2(rho) * ((eta - rho) ** 2))
    p = helper.generate_large_prime(eta)
    X = (Decimal(2) ** Decimal(gamma)) / p

    k = (p, m_max, X, rho, alpha)
    ek = (p, X, rho, alpha)
    dk = (p, m_max, rho, alpha)
    return k, ek, dk

def enc1(ek, m) -> float:
    """
    Encrypts a messsage using FAHE1 scheme.
    There is 

    Args:
        ek (float): subset of scheme key 'k'
        m (str): given message to encrypt

    Returns:
        c (float): ciphertext
    """
    p, X, rho, alpha = ek
    q = secrets.randbelow(int(X) + 1)
    noise = secrets.randbits(rho)  # Correct noise generation
    M = (m << (int(rho) + int(alpha))) + noise
    n = p * q
    c = n + M
    return c

def dec1(dk, c, num_additions):
    """
    Decrypts a messsage using FAHE1 scheme.

    Args:
        dk (float): subset of scheme key 'k'
        c (float): ciphertext

    Returns:
        m (float): decrypted message (least significant bits)
    """
    p, m_max, rho, alpha = dk

    m_max_outcome = math.ceil(math.log2(num_additions * (2**dk[1])))

    # Step 1: Compute c % p
    m_full = c % p
    m_shifted = m_full >> (rho + alpha)
    m_masked = m_shifted & ((1 << m_max) - 1)

    # Step 3: Extract the least significant |m_max| bits
    m = m_shifted & ((1 << m_max_outcome) - 1)

    return m

def dec1(dk, c):
    """
    Decrypts a messsage using FAHE1 scheme.

    Args:
        dk (float): subset of scheme key 'k'
        c (float): ciphertext

    Returns:
        m (float): decrypted message (least significant bits)
    """
    p, m_max, rho, alpha = dk

    m_full = c % p
    m_shifted = m_full >> (rho + alpha)

    m_masked = m_shifted & ((1 << m_max) - 1)
    return m_shifted


def timed_keygen1(l, m_max, alpha) -> float:
    """
    Time FAHE1 key generation.

    Args:
        l (int): security parameter (lambda)
        m_max (int): maximum message size (int bits)
        alpha (int): total number of supported additions

    Returns:
        performance_time: time it takes to keygen (in millisecs)
    """
    start_time = time.perf_counter()  # Start timing
    rho = l
    eta = rho + 2 * alpha + m_max
    gamma = rho / math.log2(rho) * ((eta - rho) ** 2)
    p = helper.generate_large_prime(eta)
    X = math.ceil((Decimal(2) ** Decimal(gamma)) / p)

    k = (p, m_max, X, rho, alpha)
    ek = (p, X, rho, alpha)
    dk = (p, m_max, rho, alpha)

    end_time = time.perf_counter()  # End timing
    performance_time = (end_time - start_time) * 1000
    return performance_time



def length_enc1(l, m_max, alpha, m) -> float:
    """
    Encrypts a messsage using FAHE1 scheme.

    Args:
        ek (float): subset of scheme key 'k'
        m (str): given message to encrypt

    Returns:
        c (float): ciphertext
    """
    scheme_key = keygen1(l, m_max, alpha)  # initial keygen

    q = secrets.randbelow(int(scheme_key[2][1]) + 1)
    noise = secrets.randbelow(2 ** scheme_key[2][2] - 1)
    M = (m << (scheme_key[2][2] + scheme_key[2][3])) + noise
    n = scheme_key[2][0] * q

    c = n + M
    return c.bit_length()


def timed_enc1(l, m_max, alpha, m) -> float:
    """
    Time FAHE1 key generation.

    Args:
        l (int): security parameter (lambda)
        m_max (int): maximum message size (int bits)
        alpha (int): total number of supported additions
        m (str): given message to encrypt

    Returns:
        performance_time: time it takes to keygen (in millisecs)
    """
    scheme_key = keygen1(l, m_max, alpha)  # initial keygen

    start_time = time.perf_counter()
    q = secrets.randbelow(int(scheme_key[2][1]) + 1)
    noise = secrets.randbelow(2 ** scheme_key[2][2] - 1)
    M = (m << (scheme_key[2][2] + scheme_key[2][3])) + noise
    n = scheme_key[2][0] * q

    end_time = time.perf_counter()
    performance_time = (end_time - start_time) * 1000
    return performance_time


