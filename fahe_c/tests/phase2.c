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

// `
// Test(fahe2, fahe2_encrypt_multiple) {
//   // Initialize parameters
//   BN_CTX *ctx = BN_CTX_new();
//   fahe_params params = {128, 32, 12, 32};
//   clock_t fahe2_keygen_start_time = clock();
//   fahe2 *fahe2_instance = fahe2_init(&params);
//   clock_t fahe2_keygen_end_time = clock();
//   double fahe2_keygen_time =
//       (double)((fahe2_keygen_end_time - fahe2_keygen_start_time) /
//                CLOCKS_PER_SEC);

//   cr_assert_not_null(fahe2_instance, "fahe2_init failed");
//   debug_fahe2_init(fahe2_instance);

//   // Generate a message
//   BIGNUM **message_list = generate_message_list(fahe2_instance->msg_size,
//                                                 fahe2_instance->num_additions);
//   //   Encrypt the message
//   clock_t fahe2_encryption_start_time = clock();
//   BIGNUM **ciphertext_list =
//       fahe2_encrypt_list(fahe2_instance->key, message_list,
//                          BN_get_word(fahe2_instance->num_additions), ctx);
//   clock_t fahe2_encryption_end_time = clock();

//   double fahe2_encryption_time =
//       (double)((fahe2_encryption_end_time - fahe2_encryption_start_time) /
//                (double)(CLOCKS_PER_SEC));

//   log_message(LOG_FATAL, "KEY_GEN TIME: %d\n", fahe2_keygen_time);
//   log_message(LOG_FATAL, "Encryption Time: %d\n", fahe2_encryption_time);

//   // Print message and ciphertext to a file
//   FILE *file = fopen("ciphertext.txt", "w");
//   cr_assert_not_null(file, "Failed to open file for writing");

//   for (unsigned int i = 0; i < BN_get_word(fahe2_instance->num_additions);
//        i++) {
//     char *message_str = BN_bn2dec(message_list[i]);
//     char *ciphertext_str = BN_bn2dec(ciphertext_list[i]);

//     cr_assert_not_null(message_str, "BN_bn2dec failed for message[%u]", i);
//     cr_assert_not_null(ciphertext_str, "BN_bn2dec failed for ciphertext[%u]",
//                        i);

//     fprintf(file, "Message[%u]: %s\nCiphertext[%u]: %s\n", i, message_str, i,
//             ciphertext_str);
//     OPENSSL_free(message_str);
//     OPENSSL_free(ciphertext_str);
//   }
//   fclose(file);
// }

// Test(fahe2, fahe2_full_single) {
//   BN_CTX *ctx = BN_CTX_new();
//   fahe_params params = {128, 32, 6, 32};
//   fahe2 *fahe2_instance = fahe2_init(&params);
//   cr_assert_not_null(fahe2_instance, "fahe2_init failed");
//   debug_fahe2_init(fahe2_instance);

//   // Generate a message
//   BIGNUM *message = generate_big_message(fahe2_instance->msg_size);
//   cr_assert_not_null(message, "generate_big_message failed");
//   print_bn("MESSAGE", message);
//   printf("Message size:%d\n", BN_num_bits(message));
//   char *message_string = BN_bn2dec(message);
//   cr_assert_not_null(message_string, "BN_bn2dec failed for message");

//   // Encrypt the message
//   BIGNUM *ciphertext = fahe2_encrypt(fahe2_instance->key, message, ctx);
//   cr_assert_not_null(ciphertext, "fahe2_encrypt failed");
//   char *ciphertext_str = BN_bn2dec(ciphertext);
//   cr_assert_not_null(ciphertext_str, "BN_bn2dec failed for ciphertext");

//   // Print message and ciphertext to a file
//   FILE *file = fopen("ciphertext.txt", "w");
//   if (file) {
//     fprintf(
//         file,
//         "Message: %s\nMessage Size: %d\nCiphertext: %s\nCiphertext Size: %d\n",
//         message_string, BN_num_bits(message), ciphertext_str,
//         BN_num_bits(ciphertext));
//     fclose(file);
//   } else {
//     fprintf(stderr, "Failed to open file for writing\n");
//   }

//   // Decrypt the message
//   BIGNUM *decrypted_message =
//       fahe2_decrypt(fahe2_instance->key, ciphertext, ctx);
//   cr_assert_not_null(decrypted_message, "fahe2_decrypt failed");
//   print_bn("UNENCRYPTED MESSAGE", decrypted_message);

//   // Compare the original message with the decrypted message
//   printf("Debug: Comparing original message and decrypted message\n");
//   if (BN_cmp(message, decrypted_message) == 0) {
//     printf("Debug: Messages match!\n");
//   } else {
//     printf("Debug: Messages do not match!\n");
//   }
//   cr_assert(BN_cmp(message, decrypted_message) == 0);

//   BN_free(message);
//   BN_free(ciphertext);
//   BN_free(decrypted_message);
//   OPENSSL_free(message_string);
//   OPENSSL_free(ciphertext_str);
// }

Test(fahe2, fahe2_full_multiple) {
  // Initialize parameters
  BN_CTX *ctx = BN_CTX_new();
  fahe_params params = {128, 32, 6, 32};
  fahe2 *fahe2_instance = fahe2_init(&params);
  cr_assert_not_null(fahe2_instance, "fahe2_init failed");
  debug_fahe2_init(fahe2_instance);

  // Generate a list of messages
  BIGNUM **message_list = generate_message_list(fahe2_instance->msg_size,
                                                fahe2_instance->num_additions);
  cr_assert_not_null(message_list, "generate_message_list failed");

  // Encrypt the message list
  BIGNUM **ciphertext_list =
      fahe2_encrypt_list(fahe2_instance->key, message_list,
                     BN_get_word(fahe2_instance->num_additions), ctx);
  cr_assert_not_null(ciphertext_list, "fahe2_encrypt_list failed");

//   Decrypt the message list
  BIGNUM **decrypted_msg_list = fahe2_dec_list(
      fahe2_instance->key.p, fahe2_instance->key.m_max,
      fahe2_instance->key.rho, fahe2_instance->key.alpha, ciphertext_list,
      fahe2_instance->num_additions);
  cr_assert_not_null(decrypted_msg_list, "fahe2_dec_list_op failed");

  // Compare the original message with the decrypted message
  for (unsigned int i = 0; i < BN_get_word(fahe2_instance->num_additions);
  i++) {
      cr_assert(BN_cmp(message_list[i], decrypted_msg_list[i]) == 0,
                "Decryption failed for message[%u]", i);
  }

//   Clean up
  for (unsigned int i = 0; i < BN_get_word(fahe2_instance->num_additions);
  i++) {
      BN_free(message_list[i]);
      BN_free(ciphertext_list[i]);
      BN_free(decrypted_msg_list[i]);
  }
  free(message_list);
  free(ciphertext_list);
  free(decrypted_msg_list);
  fahe2_free_op(fahe2_instance);
}