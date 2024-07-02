
import math
import secrets
from fahe1lol import dec1, enc1, keygen1

m_max = 32
k, ek, dk = keygen1(128, m_max, 6)
gamma = 128 / math.log2(128) * (((128 + 2.0 * 6 + m_max) - 128) ** 2.0)
m_sum = 0
c_sum = 0
print("MAX:", gamma)
for i in range(2):
    
    m = secrets.randbelow(2**m_max - 1)
    c = enc1(ek, m)
    m_sum += m
    c_sum += c

c_outcome = dec1(dk, c_sum)
print("M Total: ", m_sum)
print("Decoding Total: ", c_outcome)
print("TOTAL SIZE: ", c_sum.bit_length())

# """Test the encoding message."""

# m2 = secrets.randbelow(2**m_max - 1)
# print("\nEncoding1: ", m)
# print("Encoding2: ", m2)


# c2 = enc1(ek, m2)
# c_length = c.bit_length()
# c_length2 = c2.bit_length()



# print("Length of ciphertext1 (in bits):", c_length)
# print("Length of ciphertext2 (in bits):", c_length2)

# m_total = m + m2
# c_total = c + c2
# c_total_length = c_total.bit_length()
# print("Length of total ciphertext (in bits):", c_total_length)


# m_outcome = dec1(dk, c)
# m2_outcome = dec1(dk, c2)


# print("Decoding1: ", m_outcome)
# print("Decoding2: ", m2_outcome)
    
# total_outcome = m_outcome + m2_outcome

# print("Decoding Total: ", total_outcome)
# print("M Total: ", m_total)
