#include <criterion/criterion.h>
#include <math.h>
#include <stdio.h>

#include "fahe1.h"
#include "helper.h"

/*
This file is meant for the initial testing of fahe1.c and its corresponding
helper.c functions. Examples of the code in here include:
    - Phase 1 test helper functions for phase 1 tests debugging
    - fahe1.c single function tests
    - fahe1.c encrypting and decrypting and addition
    - fahe1.c keygeneration
*/

// Helper functions
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

void print_bn_list(const char *label, BIGNUM **bn_list, unsigned int len) {
  for (unsigned int i = 0; i < len; i++) {
    char *bn_str = BN_bn2dec(bn_list[i]);
    if (bn_str) {
      fprintf(stdout, "%s[%u]: %s\n", label, i, bn_str);
      OPENSSL_free(bn_str);
    } else {
      fprintf(stderr, "Error converting BIGNUM to decimal string at index %u\n",
              i);
    }
  }
}

void write_messages_to_file(BIGNUM **message_list, unsigned int num_msgs,
                            const char *filename) {
  FILE *file = fopen(filename, "w");
  if (!file) {
    fprintf(stderr, "Failed to open file for writing\n");
    exit(EXIT_FAILURE);
  }

  for (unsigned int i = 0; i < num_msgs; i++) {
    char *msg_str = BN_bn2dec(message_list[i]);
    if (msg_str) {
      fprintf(file, "%s", msg_str);
      if (i < num_msgs - 1) {
        fprintf(file, ",");
      }
      OPENSSL_free(msg_str);
    } else {
      fprintf(stderr, "Error converting BIGNUM to string\n");
      fclose(file);
      exit(EXIT_FAILURE);
    }
  }

  fclose(file);
}
// Phase 1 Tests --------------

Test(public, create_public_test) {
  BIGNUM *num_msgs = BN_new();
  BN_set_word(num_msgs, 32);
  unsigned int message_size = 32;

  BIGNUM **message_list = generate_message_list(message_size, num_msgs);
  if (!message_list) {
    fprintf(stderr, "Failed to generate message list\n");
    exit(EXIT_FAILURE);
  }

  const char *filename = "../public/mintest.txt";  // Adjust the path as needed
  write_messages_to_file(message_list, BN_get_word(num_msgs), filename);

  // Free allocated BIGNUMs
  for (unsigned int i = 0; i < BN_get_word(num_msgs); i++) {
    BN_free(message_list[i]);
  }
  free(message_list);
  BN_free(num_msgs);
}
// arg 1: name of test suite, arg 2: test name
Test(fahe1, fahe1_init) {
  fahe_params params = {128, 32, 6, 32};
  fahe1 *fahe1_instance = fahe1_init(&params);
  debug_fahe_init(fahe1_instance);
  fahe1_free(fahe1_instance);
}

Test(fahe1, fahe1_full_single) {
  fahe_params params = {128, 32, 6, 32};
  fahe1 *fahe1_instance = fahe1_init(&params);
  cr_assert_not_null(fahe1_instance, "fahe1_init failed");
  debug_fahe_init(fahe1_instance);

  // Generate a message
  BIGNUM *message = generate_big_message(fahe1_instance->msg_size);
  cr_assert_not_null(message, "generate_big_message failed");
  print_bn("MESSAGE", message);
  printf("Message size:%d\n", BN_num_bits(message));
  char *message_string = BN_bn2dec(message);
  cr_assert_not_null(message_string, "BN_bn2dec failed for message");

  // Encrypt the message
  BIGNUM *ciphertext =
      fahe1_enc(fahe1_instance->key.p, fahe1_instance->key.X,
                fahe1_instance->key.rho, fahe1_instance->key.alpha, message);
  cr_assert_not_null(ciphertext, "fahe1_enc failed");
  char *ciphertext_str = BN_bn2dec(ciphertext);
  cr_assert_not_null(ciphertext_str, "BN_bn2dec failed for ciphertext");

  // Print message and ciphertext to a file
  FILE *file = fopen("ciphertext.txt", "w");
  if (file) {
    fprintf(file,
            "Message: %s\nMessage Size: %d\nCiphertext: %s\nCiphertext Size: "
            "%d\n",
            message_string, BN_num_bits(message), ciphertext_str,
            BN_num_bits(ciphertext));
    fclose(file);
  } else {
    fprintf(stderr, "Failed to open file for writing\n");
  }

  // Decrypt the message
  BIGNUM *decrypted_message =
      fahe1_dec(fahe1_instance->key.p, fahe1_instance->key.m_max,
                fahe1_instance->key.rho, fahe1_instance->key.alpha, ciphertext);
  cr_assert_not_null(decrypted_message, "fahe1_dec failed");
  print_bn("UNENCRYPTED MESSAGE", decrypted_message);

  // Compare the original message with the decrypted message
  printf("Debug: Comparing original message and decrypted message\n");
  if (BN_cmp(message, decrypted_message) == 0) {
    printf("Debug: Messages match!\n");
  } else {
    printf("Debug: Messages do not match!\n");
  }
  cr_assert(BN_cmp(message, decrypted_message) == 0);
  // Clean up

  BN_free(message);
  BN_free(ciphertext);
  BN_free(decrypted_message);
  OPENSSL_free(message_string);
  OPENSSL_free(ciphertext_str);
}

Test(fahe1, fahe1_enc_multiple) {
  // lambda, m_max, alpha, msg_size
  fahe_params params = {128, 32, 6, 32};
  fahe1 *fahe1_instance = fahe1_init(&params);
  cr_assert_not_null(fahe1_instance, "fahe1_init failed");
  debug_fahe_init(fahe1_instance);

  // Generate a list of messages
  BIGNUM **message_list = generate_message_list(fahe1_instance->msg_size,
                                                fahe1_instance->num_additions);
  cr_assert_not_null(message_list, "generate_message_list failed");

  //   print_bn_list("MESSAGE", message_list,
  //   BN_get_word(fahe1_instance->num_additions));

  BIGNUM **ciphertext_list = fahe1_enc_list(
      fahe1_instance->key.p, fahe1_instance->key.X, fahe1_instance->key.rho,
      fahe1_instance->key.alpha, message_list, fahe1_instance->num_additions);
  cr_assert_not_null(ciphertext_list, "fahe1_enc_list failed");

  //   print_bn_list("CIPHERTEXT", ciphertext_list,
  //   BN_get_word(fahe1_instance->num_additions));

  // Print messages and ciphertexts to a file
  FILE *file = fopen("ciphertext.txt", "w");
  if (file) {
    for (unsigned int i = 0; i < BN_get_word(fahe1_instance->num_additions);
         i++) {
      char *message_str = BN_bn2dec(message_list[i]);
      char *ciphertext_str = BN_bn2dec(ciphertext_list[i]);

      if (message_str && ciphertext_str) {
        fprintf(file, "Message[%u]: %s\nCiphertext[%u]: %s\n", i, message_str,
                i, ciphertext_str);
        OPENSSL_free(message_str);
        OPENSSL_free(ciphertext_str);
      } else {
        fprintf(stderr,
                "Error converting BIGNUM to decimal string at index %u\n", i);
        if (message_str) OPENSSL_free(message_str);
        if (ciphertext_str) OPENSSL_free(ciphertext_str);
      }
    }
    fclose(file);
  } else {
    fprintf(stderr, "Failed to open file for writing\n");
  }

  // Free allocated BIGNUMs
  for (unsigned int i = 0; i < BN_get_word(fahe1_instance->num_additions);
       i++) {
    BN_free(message_list[i]);
    BN_free(ciphertext_list[i]);
  }
  free(message_list);
  free(ciphertext_list);
}

// Test(fahe1, fahe1_full_multiple) {
//   fahe_params params = {128, 32, 6, 32};
//   fahe1 *fahe1_instance = fahe1_init(&params);
//   cr_assert_not_null(fahe1_instance, "fahe1_init failed");
//   debug_fahe_init(fahe1_instance);

//   // Generate a list of messages
//   BIGNUM *message_list = generate_message_list(fahe1_instance->msg_size,
//                                                fahe1_instance->num_additions);
//   print_bn_list("MESSAGE", message_list);
//   char *message_string = BN_bn2dec(message_list);
//   cr_assert_not_null(message_string, "BN_bn2dec failed for message");

//   // Encrypt the message
//   BIGNUM *ciphertext =
//       fahe1_enc(fahe1_instance->key.p, fahe1_instance->key.X,
//                 fahe1_instance->key.rho, fahe1_instance->key.alpha, message);
//   cr_assert_not_null(ciphertext, "fahe1_enc failed");
//   char *ciphertext_str = BN_bn2dec(ciphertext);
//   cr_assert_not_null(ciphertext_str, "BN_bn2dec failed for ciphertext");

//   // Print message and ciphertext to a file
//   FILE *file = fopen("ciphertext.txt", "w");
//   if (file) {
//     fprintf(file,
//             "Message: %s\nMessage Size: %d\nCiphertext: %s\nCiphertext Size:
//             "
//             "%d\n",
//             message_string, BN_num_bits(message), ciphertext_str,
//             BN_num_bits(ciphertext));
//     fclose(file);
//   } else {
//     fprintf(stderr, "Failed to open file for writing\n");
//   }

//   // Decrypt the message
//   BIGNUM *decrypted_message =
//       fahe1_dec(fahe1_instance->key.p, fahe1_instance->key.m_max,
//                 fahe1_instance->key.rho, fahe1_instance->key.alpha,
//                 ciphertext);
//   cr_assert_not_null(decrypted_message, "fahe1_dec failed");
//   print_bn("UNENCRYPTED MESSAGE", decrypted_message);

//   // Compare the original message with the decrypted message
//   printf("Debug: Comparing original message and decrypted message\n");
//   if (BN_cmp(message, decrypted_message) == 0) {
//     printf("Debug: Messages match!\n");
//   } else {
//     printf("Debug: Messages do not match!\n");
//   }
//   cr_assert(BN_cmp(message, decrypted_message) == 0);
//   // Clean up

//   BN_free(message);
//   BN_free(ciphertext);
//   BN_free(decrypted_message);
//   OPENSSL_free(message_string);
//   OPENSSL_free(ciphertext_str);
// }