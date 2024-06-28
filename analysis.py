from fahe1 import dec1, enc1, keygen1
from fahe2 import dec2, enc2, keygen2
from data_collection import output_csv_6, lambda_performance_1, m_max_performance_1, alpha_performance_1
import time, secrets
import matplotlib.pyplot as plt

rep = 100
m = 2**16 - 1



alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths = alpha_performance_1(2, 35, 1, rep, 128, 32, m)
output_csv_9(alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, 'alpha', 'rho', 'eta', 'gamma', 'keygen time/s', 'encryption time/s', 'decryption time/s', 'total time/s', 'ciphertext length in bits', file_name='alpha_performance')
