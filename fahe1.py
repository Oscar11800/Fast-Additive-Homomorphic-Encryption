from decimal import Decimal
import math
import secrets
import sys
import helper
import random
from typing import Tuple

#  Cominetti, Eduardo & Simplicio, Marcos. (2020). Fast Additive Partially Homomorphic Encryption From the Approximate Common Divisor Problem. IEEE Transactions on Information Forensics and Security. PP. 1-1. 10.1109/TIFS.2020.2981239.


def keygen(l, m_max, alpha) -> tuple[float]:
    """
    Generates a FAHE1 key.

    Args:
        lambda: security parameter
        m_max: maximum message size
        alpha: total number of supported additions
        p: a prime number of eta size bits

    Returns:
        k, ek, dk: tuple of [scheme key, encrypt key, decrypt key] respectively
    """

    rho = l
    eta = rho + 2 * alpha + m_max
    gamma = rho / math.log2(rho) * ((eta - rho) ** 2)
    p = helper.generate_large_prime(eta)
    X = Decimal(2) ** (Decimal(gamma)) / p

    k = (p, m_max, X, rho, alpha)
    ek = (p, X, rho, alpha)
    dk = (p, m_max, rho, alpha)
    return k, ek, dk


def enc(ek, m) -> float:
    """
    Encrypts a messsage using FAHE1 scheme.

    Args:
        ek (float): subset of scheme key 'k'
        m (str): given message to encrypt

    Returns:
        c (float): ciphertext
    """
    q = random.randrange(0, int(ek[1]))
    noise = secrets.randbelow(2 ** ek[2] - 1)
    M = (m << (ek[2] + ek[3])) + noise
    n = ek[0] * q
    c = n + M
    return c


def dec(dk, c):
    """
    Decrypts a messsage using FAHE1 scheme.

    Args:
        dk (float): subset of scheme key 'k'
        c (float): ciphertext

    Returns:
        m (float): decrypted message (least significant bits)
    """
    m = (c % dk[0]) >> (dk[2] + dk[3])
    return m
