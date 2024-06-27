from fahe1 import keygen1, enc1, dec1
from fahe2 import keygen2, enc2, dec2
import secrets

def additivity1(l, m_max, alpha, addition):
    m_list = []
    for i in range(addition):
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
    print('Testing fahe1. alpha = {}, therefore number of additions allowed = {}; number of additions done = {}; {}'.format(alpha, 2**(alpha-1), addition, passed))
    
def additivity2(l, m_max, alpha, addition):
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
    print('Testing fahe2. alpha = {}, therefore number of additions allowed = {}; number of additions done = {}; {}'.format(alpha, 2**(alpha-1), addition, passed))


additivity1(10, 8, 6, 2)
additivity1(10, 8, 6, 3)
additivity1(10, 8, 6, 4)

additivity2(10, 8, 6, 2)
additivity2(10, 8, 6, 3)
additivity2(10, 8, 6, 4)
