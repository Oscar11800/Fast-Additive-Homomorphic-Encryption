#include <criterion/criterion.h>
#include <math.h>
#include <openssl/bn.h>
#include <stdio.h>

#include "fahe2.h"
#include "helper.h"
#include "logger.h"

// Phase 1 Tests --------------

// // arg 1: name of test suite, arg 2: test name
// Test(fahe2, fahe2_init) {
//   fahe_params params = {128, 32, 6, 32};
//   fahe2 *fahe2_instance = fahe2_init(&params);
//   debug_fahe2_init(fahe2_instance);
//   fahe2_free(fahe2_instance);
// }

Test(fahe2, fahe2_full_single) {
  BN_CTX *ctx = BN_CTX_new();
  fahe_params params = {128, 32, 6, 32};
  clock_t fahe2_keygen_start_time = clock();
  fahe2 *fahe2_instance = fahe2_init(&params);
  clock_t fahe2_keygen_end_time = clock();
  double fahe2_keygen_time =
        (double)(fahe2_keygen_end_time - fahe2_keygen_start_time) /
        CLOCKS_PER_SEC;

  cr_assert_not_null(fahe2_instance, "fahe2_init failed");
  debug_fahe2_init(fahe2_instance);

  // Generate a message
  BIGNUM *message = generate_big_message(fahe2_instance->msg_size);
  cr_assert_not_null(message, "generate_big_message failed");
  print_bn("MESSAGE", message);
  printf("Message size:%d\n", BN_num_bits(message));
  char *message_string = BN_bn2dec(message);
  cr_assert_not_null(message_string, "BN_bn2dec failed for message");

  //   Encrypt the message
  clock_t fahe2_encryption_start_time = clock();
  BIGNUM *ciphertext = fahe2_encrypt(fahe2_instance->key, message, ctx);
  clock_t fahe2_encryption_end_time = clock();

  double fahe2_encryption_time =
        (double)(fahe2_encryption_end_time - fahe2_encryption_start_time) /
        CLOCKS_PER_SEC;


  cr_assert_not_null(ciphertext, "fahe2_encrypt failed");
  char *ciphertext_str = BN_bn2dec(ciphertext);
  cr_assert_not_null(ciphertext_str, "BN_bn2dec failed for ciphertext");

  // Print message and ciphertext to a file
  FILE *file = fopen("../assets/phase2_ciphertext.txt", "w");
  if (file) {
    fprintf(
        file,
        "Message: %s\nMessage Size: %d\nCiphertext: %s\nCiphertext Size:%d\n",
        message_string, BN_num_bits(message), ciphertext_str,
        BN_num_bits(ciphertext));
    fclose(file);
  } else {
    fprintf(stderr, "Failed to open file for writing\n");
  }

  printf("KEYGEN TIME: %f\n", fahe2_keygen_time);
  printf("ENCRYPTION TIME: %f\n", fahe2_encryption_time);

}
