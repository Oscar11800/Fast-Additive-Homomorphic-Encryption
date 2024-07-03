import random
from fahe1 import keygen1, enc1, dec1
from fahe2 import keygen2, enc2, dec2
import secrets
import matplotlib.pyplot as plt
import sys

from helper import max_num_for_bit_len


def additivity_fahe1(l, m_max, alpha, num_additions):
    """
    Test the additivity property of FAHE1.

    Args:
        l (int): Security parameter (lambda).
        m_max (int): Maximum message size (in bits).
        alpha (int): Total number of supported additions.
        num_additions (int): Number of additions to test.

    Returns:
        tuple: Contains totals of plain messages, decrypted message from ciphertexts,
               total ciphertext, type of total ciphertext, and pass/fail status.
    """
    k, ek, dk = keygen1(l, m_max, alpha)
    m_list = [random.getrandbits(m_max-12) for _ in range(num_additions)]
    c_list = [enc1(ek, m) for m in m_list]

    homomorphic_sum = sum(c_list)
    
    # Direct sum of messages
    direct_sum = sum(m_list)

    # Decrypt the homomorphic sum
    decrypted_sum = dec1(dk, homomorphic_sum)
    
    if direct_sum == decrypted_sum:
        passed = "Passed"
    else:
        passed = "Failed"
    print(
        "Testing fahe1.\nalpha = {}, therefore number of additions allowed = {}; number of additions done = {};\nTotal m directly added = {}; total m from c added = {}; {}\nbit length of c = {}, type of variable c_total = {}\n".format(
            alpha,
            2 ** (alpha - 1),
            num_additions,
            direct_sum,
            decrypted_sum,
            passed,
            homomorphic_sum.bit_length(),
            type(homomorphic_sum),
        )
    )
    return direct_sum, decrypted_sum, homomorphic_sum, type(homomorphic_sum), passed


def additivity_fahe2(l, m_max, alpha, num_additions):
    m_list = []
    for i in range(num_additions):
        m = secrets.randbelow(2**m_max - 1)
        m_list.append(m)

    c_list = []
    k, ek, dk = keygen2(l, m_max, alpha)
    for m in m_list:
        c = enc2(ek, m)
        c_list.append(c)

    c_total = sum(c_list)
    m_total = sum(m_list)
    m_outcome = dec2(dk, c_total)
    if m_total == m_outcome:
        passed = "Passed"
    else:
        passed = "Failed"
    print(
        "Testing fahe2.\nalpha = {}, therefore number of additions allowed = {}; number of additions done = {};\nTotal m directly added = {}; total m from c added = {}; {}\nbit length of c = {}, type of variable c_total = {}\n".format(
            alpha,
            2 ** (alpha - 1),
            num_additions,
            m_total,
            m_outcome,
            passed,
            c_total.bit_length(),
            type(c_total),
        )
    )
    return m_total, m_outcome, c_total, type(c_total), passed


m_totals = []
m_outcomes = []
m_pass = []
pass_indices = []
fail_indices = []
pass_number = 0
for i in range(100):
    m_total, m_outcome, c_total, type_c, passed = additivity_fahe1(128, 64, 33, 2**32)
    if passed == "Passed":
        pass_indices.append(i)
        pass_number += 1
        m_pass.append(m_outcome)
    else:
        fail_indices.append(i)
        m_totals.append(m_total)
        m_outcomes.append(m_outcome)

print("Pass rate = {}%".format(pass_number))

print("Failing pairs:")
for i in range(len(fail_indices)):
    print("index = {}, m_total = {}, m_outcome = {}".format(fail_indices[i], m_totals[i], m_outcomes[i]))

plt.scatter(pass_indices, m_pass, c="green")
plt.scatter(fail_indices, m_totals, c="blue")
plt.scatter(fail_indices, m_outcomes, c="red")
plt.grid()
plt.show()
plt.savefig('fahe1add.png')

# additivity_fahe1(128, 32, 6, 32)
# additivity_fahe1(128, 32, 6, 32)
# additivity_fahe1(128, 32, 6, 32)
# additivity_fahe1(128, 32, 6, 32)

# additivity_fahe1(128, 64, 22, 64)
# additivity_fahe1(256, 64, 32, 100)

# additivity_fahe2(32, 16, 8, 2)
# additivity_fahe2(32, 16, 8, 3)
# additivity_fahe2(32, 16, 8, 4)
