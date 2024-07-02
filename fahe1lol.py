import math
import secrets
import helper
import sympy as simp
import gmpy2
from gmpy2 import mpz, log2

def keygen1(lamb, m_max, alpha) -> tuple[float]:
    """
    Generates a FAHE1 key.

    Args:
        lamb: security parameter (lambda)
        m_max: maximum message size (int bits)
        alpha: total number of supported additions
        p: a prime number of eta size bits

    Returns:
        k, ek, dk: tuple of [scheme key, encrypt key, decrypt key] respectively
    """
    rho = lamb
    # Compute eta
    eta = mpz(rho + 2 * alpha + m_max)
    
    # Compute gamma
    log2_rho = log2(mpz(rho))
    gamma = (rho / log2_rho) * ((eta - rho) ** 2)
    
    # Pick a prime p of size eta bits
    p = simp.nextprime(2 ** (eta - 1))
    
    # Compute X using gmpy2 to handle large numbers
    log2_p = log2(mpz(p))
    log2_X = gamma - log2_p
    X = gmpy2.exp2(log2_X)
    k = (p, m_max, X, rho, alpha)
    ek = (p, X, rho, alpha)
    dk = (p, m_max, rho, alpha)
    return[k, ek, dk]

def enc1(ek, m) -> int:
    """
    Encrypts a messsage using FAHE1 scheme.

    Args:
        ek (float): subset of scheme key 'k'
        m (str): given message to encrypt

    Returns:
        c (float): ciphertext
    """
    p, X, rho, alpha = ek
    q = secrets.randbelow(int(X) + 1)
    noise = secrets.randbelow(2 ** rho)
    M = (m << (rho + alpha)) + noise
    n = p * q
    c = n + M
    return c

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

    # Step 1: Compute c mod p
    m = c % p

    # Step 2: Right shift by (rho + alpha)
    m >>= (rho + alpha)

    # Step 3: Extract the least significant |m_max| bits
    num_bits = m_max.bit_length()
    m = m & ((1 << m_max) - 1)

    return m