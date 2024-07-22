#include <criterion/criterion.h>
#include <math.h>
#include <stdio.h>
#include <time.h>

#include "fahe1.h"
#include "helper.h"
#include "logger.h"

Test(fahe1_analysis, fahe1_analysis_fahe1_full) {
  // Number of trials
  int num_trials = 10;
  // lambda, m_max, alpha, msg_size
  fahe_params params = {128, 32, 6, 32};
  int list_size = 32;
  BIGNUM *bn_list_size = BN_new();
  BN_set_word(bn_list_size, list_size);

  const char *filename = "../public/mintest.txt";
  BIGNUM **msg_list = read_bignum_list_from_file(filename, &list_size);

  double total_keygen_time = 0.0;
  double total_encryption_time = 0.0;
  double total_decryption_time = 0.0;

  for (int trial = 0; trial < num_trials; trial++) {
    // TIMED KEYGEN
    clock_t fahe1_keygen_start_time = clock();
    fahe1 *fahe1_instance = fahe1_init(&params);
    clock_t fahe1_keygen_end_time = clock();

    double fahe1_keygen_time =
        (double)(fahe1_keygen_end_time - fahe1_keygen_start_time) /
        CLOCKS_PER_SEC;
    total_keygen_time += fahe1_keygen_time;

    // TIMED ENCRYPTION
    clock_t fahe1_encryption_start_time = clock();
    BIGNUM **ciphertext_list = fahe1_enc_list(
        fahe1_instance->key.p, fahe1_instance->key.X, fahe1_instance->key.rho,
        fahe1_instance->key.alpha, msg_list, fahe1_instance->num_additions);
    clock_t fahe1_encryption_end_time = clock();
    double fahe1_encryption_time =
        (double)(fahe1_encryption_end_time - fahe1_encryption_start_time) /
        CLOCKS_PER_SEC;
    total_encryption_time += fahe1_encryption_time;

    // TIMED DECRYPTION
    clock_t fahe1_decryption_start_time = clock();
    BIGNUM **decrypted_msg_list =
        fahe1_dec_list(fahe1_instance->key.p, fahe1_instance->key.m_max,
                       fahe1_instance->key.rho, fahe1_instance->key.alpha,
                       ciphertext_list, bn_list_size);
    clock_t fahe1_decryption_end_time = clock();
    double fahe1_decryption_time =
        (double)(fahe1_decryption_end_time - fahe1_decryption_start_time) /
        CLOCKS_PER_SEC;
    total_decryption_time += fahe1_decryption_time;

    // Free resources for this trial
    for (unsigned int i = 0; i < list_size; i++) {
      BN_free(ciphertext_list[i]);
      BN_free(decrypted_msg_list[i]);
    }
    free(ciphertext_list);
    free(decrypted_msg_list);
    fahe1_free(fahe1_instance);
  }

  // Calculate averages
  double avg_keygen_time = total_keygen_time / num_trials;
  double avg_encryption_time = total_encryption_time / num_trials;
  double avg_decryption_time = total_decryption_time / num_trials;

  printf("Average Keygen time: %.6f seconds\n", avg_keygen_time);
  printf("Average Encryption time: %.6f seconds\n", avg_encryption_time);
  printf("Average Decryption time: %.6f seconds\n", avg_decryption_time);

  printf("Total Keygen time: %.6f seconds\n", total_keygen_time);
  printf("Total Encryption time: %.6f seconds\n", total_encryption_time);
  printf("Total Decryption time: %.6f seconds\n", total_decryption_time);

  // Free the last instance of bn_list_size and msg_list
  BN_free(bn_list_size);
  for (unsigned int i = 0; i < list_size; i++) {
    BN_free(msg_list[i]);
  }
  free(msg_list);
}
