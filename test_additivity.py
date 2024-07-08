import random
from fahe1 import keygen1, enc1, dec1
from fahe2 import keygen2, enc2, dec2
import secrets
import matplotlib.pyplot as plt
import sys, os

from data_collection import max_num_for_bit_len


def additivity_fahe1(m_list, num_additions, k):
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
    ek = (k[0], k[2], k[3], k[4])
    dk = (k[0], k[1], k[3], k[4])
    # c_list = [enc1(ek, m) for m in m_list]
    c_list = []


    file_exist = False

    # homomorphic_sum = sum(c_list)
    
    # Direct sum of messages
    if os.path.isfile("analysis_tests/isoutput_failing_step.txt"):
        file_exist = True
    if not file_exist:
        file = open('analysis_tests/output_failing_step.txt','w')
    direct_sum = 0
    num_carries = 0
    homomorphic_sum = 0
    decrypted_sum = 0
    i = 0
    error_occur = False
    for m in m_list:
        i += 1
        direct_sum_previous = direct_sum
        num_carries_previous = num_carries
        direct_sum += m
        if direct_sum.bit_length() > direct_sum_previous.bit_length() and i != 1:
            num_carries += 1
        c = enc1(ek, m)
        c_list.append(c)
        homomorphic_sum_previous = homomorphic_sum
        homomorphic_sum += c
        decrypted_sum_previous = decrypted_sum
        decrypted_sum = dec1(dk, homomorphic_sum, i)
        if not file_exist:
            file.write("Current sum of m = {}, current m_outcome from sum of c = {}\nPrevious sum of m = {}, previous m_outcome from sum of c = {}, m added this time = {};\nbit_length of current sum of c = {}, bit_length of previous sum of c = {}\nThis happens after {} additions; This happens after {} carries\n".format(bin(direct_sum), bin(decrypted_sum), bin(direct_sum_previous), bin(decrypted_sum_previous), bin(m), homomorphic_sum.bit_length(), homomorphic_sum_previous.bit_length(), i, num_carries))
        if direct_sum != decrypted_sum:
            if not error_occur:
                print("Error occurs.\nCurrent sum of m = {}, but current m_outcome from sum of c = {}\nPrevious sum of m = {}, previous m_outcome from sum of c = {}, m added this time = {};\nThis happens after {} additions; This happens after {} carries".format(bin(direct_sum), bin(decrypted_sum), bin(direct_sum_previous), bin(decrypted_sum_previous), bin(m), i, num_carries))
                if not file_exist:
                    file.write("Error occurs at this step.\nCurrent sum of c = {}\nPrevious sum of c = {}\nc added this time = {}\n".format(bin(homomorphic_sum), bin(homomorphic_sum_previous), bin(c)))
            error_occur = True
        if not file_exist:
            file.write("\n\n")
    if not file_exist:
        file.close()
    # Decrypt the homomorphic sum
    # decrypted_sum = dec1(dk, homomorphic_sum, num_additions)
    
    if direct_sum == decrypted_sum:
        passed = "Passed"
    else:
        passed = "Failed"
    print(
        "Testing fahe1.\nalpha = {}, therefore number of additions allowed = {}; number of additions done = {};\nTotal m directly added = {}; total m from c added = {}; Number of carries = {}; {}\nbit length of c = {}, type of variable c_total = {}\n".format(
            k[4],
            2 ** (alpha - 1),
            num_additions,
            direct_sum,
            decrypted_sum,
            num_carries,
            passed,
            homomorphic_sum.bit_length(),
            type(homomorphic_sum),
        )
    )
    return direct_sum, decrypted_sum, homomorphic_sum, type(homomorphic_sum), passed, num_carries


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
fail_carries_list = []
pass_number = 0
m_max = 32
num_additions = 32
alpha = 6
l = 128
m_list = [random.getrandbits(m_max) for _ in range(num_additions)]
k, ek, dk = keygen1(l, m_max, alpha)
for i in range(100):
    m_total, m_outcome, c_total, type_c, passed, num_carries = additivity_fahe1(m_list, num_additions, k)
    if passed == "Passed":
        pass_indices.append(i)
        pass_number += 1
        m_pass.append(m_outcome)
    else:
        fail_indices.append(i)
        m_totals.append(m_total)
        m_outcomes.append(m_outcome)
        fail_carries_list.append(num_carries)

        


print("Failing pairs:")
for i in range(len(fail_indices)):
    print("index = {}, m_total = {}, m_outcome = {}, num_carries = {}".format(fail_indices[i], bin(m_totals[i]), bin(m_outcomes[i]), fail_carries_list[i]))

print("Pass rate = {}%".format(pass_number))

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
