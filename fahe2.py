from decimal import Decimal
import math
import secrets
import sys
import helper
import random
from typing import Tuple
from Crypto.Util import number


def keygen2(l, m_max, alpha) -> tuple[float]:
    """
    Generates a FAHE2 key.
    There is random process within this function (large prime p is random)

    rho: noise parameter
    eta: secret key size
    gamma: final ciphertext max size

    Args:
        l: security parameter
        m_max: maximum message size
        alpha: total number of supported additions
        p: a prime number of eta size bits

    Returns:
        k, ek, dk: tuple of [scheme key, encrypt key, decrypt key] respectively
    """

    rho = l + alpha + m_max
    eta = rho + alpha
    gamma = int(rho / math.log2(rho) * ((eta - rho) ** 2))
    p = number.getPrime(eta)
    X = (Decimal(2) ** Decimal(gamma)) / p
    pos = secrets.randbelow(l + 2)  # +2 because lambda is inclusive

    k = (p, X, pos, m_max, l, alpha)
    ek = (p, X, pos, m_max, l, alpha)
    dk = (p, pos, m_max, alpha)
    print("Generated FAHE2 KEY!")
    return k, ek, dk


def enc2(ek, m):
    """
    Encrypts a messsage using FAHE2 scheme.

    Args:
        ek (float): subset of scheme key 'k'
        m (str): given message to encrypt

    Returns:
        c (float): ciphertext
    """
    p, X, pos, m_max, l, alpha = ek
    q = secrets.randbelow(int(X) + 1)
    noise1 = secrets.randbits(pos)
    noise2 = secrets.randbits(l - pos)
    # print("Generated noise!")
    M = (noise2 << (pos + m_max + alpha)) + (m << (pos + alpha)) + noise1
    n = p * q
    c = n + M
    # print("Encrypted!")
    return c


def dec2(dk, c):
    """
    Decrypts a messsage using FAHE2 scheme.

    Args:
        dk (float): subset of scheme key 'k'
        c (float): ciphertext

    Returns:
        m (float): decrypted message (least significant bits)
    """
    p, pos, m_max, alpha = dk

    pos_alpha = int(pos + alpha)
    m_first = (c % p)
    m_shifted = m_first >> pos_alpha
    m_masked = m_shifted & ((1 << m_max) - 1)
    
    # Debug statements
    print(f"Decryption parameters: p={p}, pos={pos}, m_max={m_max}, alpha={alpha}")
    print(f"Intermediate values: c % p = {c % p}, pos + alpha = {pos_alpha}")
    print(f"m_full (before masking): {m_shifted}")
    print(f"Decrypted message (m): {m_masked}")

    return m_masked
