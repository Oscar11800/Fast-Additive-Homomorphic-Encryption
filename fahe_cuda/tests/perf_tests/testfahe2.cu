#include <criterion/criterion.h>
#include <math.h>
#include <stdio.h>
#include <time.h>

#include "fahe2.h"
#include "helper.h"
#include "logger.h"

// TestSuite(fahe2, .init = thread_setup, .fini = thread_teardown);

Test(fahe2, fahe2_analysis_fahe2full) {
  int num_trials = 1000;
  fahe_params params = {128, 32, 10, 32};
  int list_size = 32;
  BIGNUM *bn_list_size = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!bn_list_size || !ctx) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  BN_set_word(bn_list_size, list_size);

  const char *filename = "../assets/mintest.txt";
  BIGNUM **msg_list = read_bignum_list_from_file(filename, &list_size);
  if (!msg_list) {
    log_message(LOG_FATAL, "Failed to read BIGNUM list from file\n");
    BN_free(bn_list_size);
    BN_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  double total_keygen_time = 0.0;
  double total_encryption_time = 0.0;
  double total_decryption_time = 0.0;

  for (int trial = 0; trial < num_trials; trial++) {
    // TIMED KEYGEN
    clock_t fahe2_keygen_start_time = clock();
    fahe2 *fahe2_instance = fahe2_init(&params);
    clock_t fahe2_keygen_end_time = clock();

    if (!fahe2_instance) {
      log_message(LOG_FATAL, "Failed to initialize FAHE2 instance\n");
      break;
    }

    double fahe2_keygen_time =
        (double)(fahe2_keygen_end_time - fahe2_keygen_start_time) /
        CLOCKS_PER_SEC;
    total_keygen_time += fahe2_keygen_time;

    // TIMED ENCRYPTION
    clock_t fahe2_encryption_start_time = clock();
    BIGNUM **ciphertext_list =
        fahe2_encrypt_list(fahe2_instance->key, msg_list,
                           BN_get_word(fahe2_instance->num_additions), ctx);
    clock_t fahe2_encryption_end_time = clock();

    if (!ciphertext_list) {
      log_message(LOG_FATAL, "Encryption failed\n");
      fahe2_free(fahe2_instance);
      break;
    }

    double fahe2_encryption_time =
        (double)(fahe2_encryption_end_time - fahe2_encryption_start_time) /
        CLOCKS_PER_SEC;
    total_encryption_time += fahe2_encryption_time;

    // TIMED DECRYPTION
    clock_t fahe2_decryption_start_time = clock();
    BIGNUM **decrypted_msg_list = fahe2_decrypt_list(
        fahe2_instance->key, ciphertext_list, bn_list_size, ctx);
    clock_t fahe2_decryption_end_time = clock();

    if (!decrypted_msg_list) {
      log_message(LOG_FATAL, "Decryption failed\n");
      for (unsigned int i = 0; i < list_size; i++) {
        BN_free(ciphertext_list[i]);
      }
      free(ciphertext_list);
      fahe2_free(fahe2_instance);
      break;
    }

    double fahe2_decryption_time =
        (double)(fahe2_decryption_end_time - fahe2_decryption_start_time) /
        CLOCKS_PER_SEC;
    total_decryption_time += fahe2_decryption_time;

    // Free resources for this trial
    for (unsigned int i = 0; i < list_size; i++) {
      BN_free(ciphertext_list[i]);
      BN_free(decrypted_msg_list[i]);
    }
    free(ciphertext_list);
    free(decrypted_msg_list);
    fahe2_free(fahe2_instance);
  }

  // Calculate averages
  double avg_keygen_time = total_keygen_time / num_trials;
  double avg_encryption_time = total_encryption_time / num_trials;
  double avg_decryption_time = total_decryption_time / num_trials;

  print_test_table("FAHE2 Test", params, num_trials, avg_keygen_time,
                   avg_encryption_time, avg_decryption_time, total_keygen_time,
                   total_encryption_time, total_decryption_time);

  // Free the last instance of bn_list_size and msg_list
  BN_free(bn_list_size);
  for (unsigned int i = 0; i < list_size; i++) {
    BN_free(msg_list[i]);
  }
  free(msg_list);
  BN_CTX_free(ctx);
}