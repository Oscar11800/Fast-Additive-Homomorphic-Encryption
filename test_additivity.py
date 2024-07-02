from fahe1 import keygen1, enc1, dec1
from fahe2 import keygen2, enc2, dec2
import secrets
import matplotlib.pyplot as plt
import sys

def additivity_fahe1(l, m_max, alpha, num_additions):
    m_list = []
    for i in range(num_additions):
        m = secrets.randbelow(2**m_max - 1)
        m_list.append(m)

    c_list = []
    k, ek, dk = keygen1(l, m_max, alpha)
    for m in m_list:
        c = enc1(ek, m)
        c_list.append(c)

    c_total = sum(c_list)
    m_total = sum(m_list)
    m_outcome = dec1(dk, c_total)
    if m_total == m_outcome:
        passed = 'Passed'
    else:
        passed = 'Failed'
    print('Testing fahe1.\nalpha = {}, therefore number of additions allowed = {}; number of additions done = {};\nTotal m directly added = {}; total m from c added = {}; {}\nbit length of c = {}, type of variable c_total = {}\n'.format(alpha, 2**(alpha-1), num_additions, m_total, m_outcome, passed, c_total.bit_length(), type(c_total)))
    return m_total, m_outcome, c_total, type(c_total), passed
    
def additivity_fahe2(l, m_max, alpha, addition):
    m_list = []
    for i in range(addition):
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
        passed = 'Passed'
    else:
        passed = 'Failed'
        exit(1)
    print('Testing fahe2.\nalpha = {}, therefore number of additions allowed = {}; number of additions done = {};\nTotal m directly added = {}; total m from c added = {}; {}\ntype of variable c_total = {}\n'.format(alpha, 2**(alpha-1), addition, m_total, m_outcome, passed, type(c_total)))

m_totals = []
m_outcomes = []
indices = []
pass_number = 0
for i in range(100):
    m_total, m_outcome, c_total, type_c, passed = additivity_fahe1(128, 32, 8, 128)
    if passed == 'Passed':
        pass_number += 1
    m_totals.append(m_total)
    m_outcomes.append(m_outcome)
    indices.append(i)
print('Pass rate = {}%'.format(pass_number))

plt.scatter(indices, m_totals, c='blue')
plt.scatter(indices, m_outcomes, c='red')
plt.grid()
plt.show()

# additivity_fahe1(128, 32, 6, 32)
# additivity_fahe1(128, 32, 6, 32)
# additivity_fahe1(128, 32, 6, 32)
# additivity_fahe1(128, 32, 6, 32)

# additivity_fahe1(128, 64, 22, 64)
# additivity_fahe1(256, 64, 32, 100)

# additivity_fahe2(32, 16, 8, 2)
# additivity_fahe2(32, 16, 8, 3)
# additivity_fahe2(32, 16, 8, 4)
