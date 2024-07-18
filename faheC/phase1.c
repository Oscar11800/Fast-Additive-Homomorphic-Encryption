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

Test(fahe1_fahe1_init, fahe1_init00) {
  fahe_params params = {128, 32, 6, 32};
  fahe1 *fahe1_instance = fahe1_init(&params);
  debug_fahe_init(fahe1_instance);
  fahe1_free(fahe1_instance);
}

Test(fahe_fahe1_enc, fahe1_enc00) {
  fahe_params params = {128, 32, 6, 32};
  fahe1 *fahe1_instance = fahe1_init(params);
  debug_fahe_init(fahe1_instance);
//   fahe1 *fahe1_instance = &fahe->fahe1_instance;
//   int message = generate_int_message(fahe1_instance->msg_size);
  // Encrypt the message
//   BIGNUM *ciphertext = fahe1_enc(
//       fahe1_instance->key.p, fahe1_instance->key.X,
//       fahe1_instance->key.rho, fahe1_instance->key.alpha, message);
//   char *ciphertext_str = BN_bn2dec(ciphertext);

//   // Print message and ciphertext to a file
//   FILE *file = fopen("ciphertext.txt", "w");
//   if (file) {
//     fprintf(
//         file,
//         "Message: %d\nMessage Size: %u\nCiphertext: %s\nCiphertext Size: %d\n",
//         message, bit_length(message), ciphertext_str, BN_num_bits(ciphertext));
//     fclose(file);
//   } else {
//     fprintf(stderr, "Failed to open file for writing\n");
//   }

  // Free the allocated memory
//   OPENSSL_free(ciphertext_str);
//   BN_free(ciphertext);
  fahe1_free(fahe1_instance);
}