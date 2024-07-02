from fahe1 import dec1, enc1, keygen1
from fahe2 import dec2, enc2, keygen2
from data_collection import alpha_performance_2, output_csv_6, output_csv_11, lambda_performance_1, m_max_performance_1, alpha_performance_1
import time, secrets
import matplotlib.pyplot as plt

rep = 100
m = 2**16 - 1

def run_analysis_fahe1():
    # FAHE1
    alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes = alpha_performance_1(5, 35, 5, rep, 128, 32, m)
    output_csv_11(alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes, 'alpha', 'rho', 'eta', 'gamma', 'keygen time/s', 'encryption time/s', 'decryption time/s', 'total time/s', 'ciphertext length in bits', 'lambda', 'm_max', file_name='fahe1_alpha_performance_1')

    alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes = alpha_performance_1(5, 35, 5, rep, 128, 64, m)
    output_csv_11(alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes, 'alpha', 'rho', 'eta', 'gamma', 'keygen time/s', 'encryption time/s', 'decryption time/s', 'total time/s', 'ciphertext length in bits', 'lambda', 'm_max', file_name='fahe1_alpha_performance_2')

    alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes = alpha_performance_1(5, 35, 5, rep, 256, 32, m)
    output_csv_11(alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes, 'alpha', 'rho', 'eta', 'gamma', 'keygen time/s', 'encryption time/s', 'decryption time/s', 'total time/s', 'ciphertext length in bits', 'lambda', 'm_max', file_name='fahe1_alpha_performance_3')

    alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes = alpha_performance_1(5, 35, 5, rep, 256, 64, m)
    output_csv_11(alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes, 'alpha', 'rho', 'eta', 'gamma', 'keygen time/s', 'encryption time/s', 'decryption time/s', 'total time/s', 'ciphertext length in bits', 'lambda', 'm_max', file_name='fahe1_alpha_performance_4')

def run_analysis_fahe2():
    # FAHE2
    alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes = alpha_performance_2(5, 35, 5, rep, 128, 32, m)
    output_csv_11(alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes, 'alpha', 'rho', 'eta', 'gamma', 'keygen time/s', 'encryption time/s', 'decryption time/s', 'total time/s', 'ciphertext length in bits', 'lambda', 'm_max', file_name='fahe2_alpha_performance_1')

    alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes = alpha_performance_2(5, 35, 5, rep, 128, 64, m)
    output_csv_11(alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes, 'alpha', 'rho', 'eta', 'gamma', 'keygen time/s', 'encryption time/s', 'decryption time/s', 'total time/s', 'ciphertext length in bits', 'lambda', 'm_max', file_name='fahe2_alpha_performance_2')

    alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes = alpha_performance_2(5, 35, 5, rep, 256, 32, m)
    output_csv_11(alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes, 'alpha', 'rho', 'eta', 'gamma', 'keygen time/s', 'encryption time/s', 'decryption time/s', 'total time/s', 'ciphertext length in bits', 'lambda', 'm_max', file_name='fahe2_alpha_performance_3')

    alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes = alpha_performance_2(5, 35, 5, rep, 256, 64, m)
    output_csv_11(alphas, rhos, etas, gammas, keygen_times, enc_times, dec_times, total_times, clengths, lambdas, m_maxes, 'alpha', 'rho', 'eta', 'gamma', 'keygen time/s', 'encryption time/s', 'decryption time/s', 'total time/s', 'ciphertext length in bits', 'lambda', 'm_max', file_name='fahe2_alpha_performance_4')
    
# uncomment this to run FAHE1 analysis
run_analysis_fahe1() 

run_analysis_fahe2()