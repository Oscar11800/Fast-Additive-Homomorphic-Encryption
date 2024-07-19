#include <criterion/criterion.h>
#include <math.h>
#include <stdio.h>

#include "fahe1.h"
#include "helper.h"

// helpers
void debug_fahe_init(fahe1 *fahe1_instance) {
  if (!fahe1_instance) {
    fprintf(stderr, "ERROR DEBUGGING: FAHE instance is NULL.\n");
    return;
  }
  printf("FAHE1 Instance:\n");
  printf("lambda: %d\n", fahe1_instance->key.lambda);
  printf("m_max: %d\n", fahe1_instance->key.m_max);
  printf("alpha: %d\n", fahe1_instance->key.alpha);
  printf("msg_size: %u\n", fahe1_instance->msg_size);

  // Print num_additions
  char *num_additions_str = BN_bn2dec(fahe1_instance->num_additions);
  if (num_additions_str) {
    printf("num_additions: %s\n", num_additions_str);
    OPENSSL_free(num_additions_str);
  } else {
    fprintf(stderr, "Error converting num_additions to string\n");
  }
}

// Helper function to print a BIGNUM
void print_bn(const char *label, BIGNUM *bn) {
  char *bn_str = BN_bn2dec(bn);
  if (bn_str) {
    fprintf(stdout, "%s: %s\n", label, bn_str);
    OPENSSL_free(bn_str);  // Free the allocated string
  } else {
    fprintf(stderr, "Error converting BIGNUM to decimal string\n");
  }
}

// Test(fahe1_fahe1_init, fahe1_init00) {
//   fahe_params params = {128, 32, 6, 32};
//   fahe1 *fahe1_instance = fahe1_init(&params);
//   debug_fahe_init(fahe1_instance);
//   fahe1_free(fahe1_instance);
// }

Test(fahe_fahe1_enc, fahe1_enc00) {
    fahe_params params = {128, 64, 6, 64};
    fahe1 *fahe1_instance = fahe1_init(&params);
    cr_assert_not_null(fahe1_instance, "fahe1_init failed");


    debug_fahe_init(fahe1_instance);

    // Generate a message
    BIGNUM *message = generate_big_message(fahe1_instance->msg_size);
    cr_assert_not_null(message, "generate_big_message failed");
    print_bn("MESSAGE", message);

    char *message_string = BN_bn2dec(message);
    cr_assert_not_null(message_string, "BN_bn2dec failed for message");

    // Encrypt the message
    BIGNUM *ciphertext = fahe1_enc(
        fahe1_instance->key.p, fahe1_instance->key.X,
        fahe1_instance->key.rho, fahe1_instance->key.alpha, message);
    cr_assert_not_null(ciphertext, "fahe1_enc failed");

    char *ciphertext_str = BN_bn2dec(ciphertext);
    cr_assert_not_null(ciphertext_str, "BN_bn2dec failed for ciphertext");

    // Print message and ciphertext to a file
    FILE *file = fopen("ciphertext.txt", "w");
    if (file) {
        fprintf(file, "Message: %s\nMessage Size: %d\nCiphertext: %s\nCiphertext Size: %d\n",
                message_string, BN_num_bits(message), ciphertext_str, BN_num_bits(ciphertext));
        fclose(file);
    } else {
        fprintf(stderr, "Failed to open file for writing\n");
    }

    // Free allocated memory
    BN_free(message);
    OPENSSL_free(message_string);
    BN_free(ciphertext);
    OPENSSL_free(ciphertext_str);
    fahe1_free(fahe1_instance);
}