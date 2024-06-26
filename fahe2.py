from decimal import Decimal
import math
import secrets
import sys
import helper
import random
from typing import Tuple


def keygen(l, m_max, alpha) -> tuple[float]:
    """
    Generates a FAHE2 key.

    Args:
        lambda: security parameter
        m_max: maximum message size
        alpha: total number of supported additions
        p: a prime number of eta size bits

    Returns:
        k, ek, dk: tuple of [scheme key, encrypt key, decrypt key] respectively
    """

    rho = l + alpha + m_max
    eta = rho + alpha
    gamma = rho / math.log2(rho) * ((eta - rho) ** 2)
    p = helper.generate_large_prime(eta)
    X = (Decimal(2) ** (Decimal(gamma))) / p
    pos = random.randint(0, l)

    k = (p, X, pos, m_max, l, alpha)
    ek = (p, X, pos, m_max, l, alpha)
    dk = (p, pos, m_max, alpha)
    return k, ek, dk


def enc(ek, m):
    """
    Encrypts a messsage using FAHE2 scheme.

    Args:
        ek (float): subset of scheme key 'k'
        m (str): given message to encrypt

    Returns:
        c (float): ciphertext
    """
    q = random.randrange(0, int(ek[1]))
    noise1 = secrets.randbelow(2 ** ek[2] - 1)
    noise2 = secrets.randbelow(2 ** (ek[4] - ek[2]) - 1)
    M = (noise2 << (ek[2] + ek[3] + ek[5])) + (m << (ek[2] + ek[5])) + noise1
    n = ek[0] * q
    c = n + M
    return c


def dec(dk, c):
    """
    Decrypts a messsage using FAHE2 scheme.

    Args:
        dk (float): subset of scheme key 'k'
        c (float): ciphertext

    Returns:
        m (float): decrypted message (least significant bits)
    """
    m_full_string = bin((c % dk[0]) >> (dk[1] + dk[3]))
    m = int(m_full_string[len(m_full_string) - m_max :], 2)
    return m

