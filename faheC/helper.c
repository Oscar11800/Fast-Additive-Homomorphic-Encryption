#include <math.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "logger.h"

BIGNUM *rand_num_below(const BIGNUM *upper_bound) {
  BIGNUM *rand_bn = BN_new();
  if (!rand_bn) {
    log_message(LOG_FATAL, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }

  if (!BN_rand_range(rand_bn, upper_bound)) {
    log_message(LOG_FATAL, "BN_rand_range failed\n");
    BN_free(rand_bn);
    exit(EXIT_FAILURE);
  }

  return rand_bn;
}

BIGNUM *rand_bits_below(unsigned int bitlength) {
  BIGNUM *rand_bn = BN_new();
  if (!rand_bn) {
    log_message(LOG_FATAL, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }

  if (!BN_rand(rand_bn, bitlength, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
    log_message(LOG_FATAL, "BN_rand failed\n");
    BN_free(rand_bn);
    exit(EXIT_FAILURE);
  }

  return rand_bn;
}

BIGNUM *generate_big_message(unsigned int message_size) {
  BIGNUM *BN_message = BN_new();
  if (!BN_message) {
    log_message(LOG_FATAL, "BNmessage failed\n");
    BN_free(BN_message);
    exit(EXIT_FAILURE);
  }

  // Generate a random number of `message_size` bits
  if (!BN_rand(BN_message, message_size, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
    log_message(LOG_FATAL, "BNmessage failed\n");
    BN_free(BN_message);
    exit(EXIT_FAILURE);
  }

  return BN_message;
}

BIGNUM **generate_message_list(unsigned int message_size,
                               BIGNUM *num_messages) {
  BIGNUM **message_list = (BIGNUM **)malloc(BN_get_word(num_messages) * sizeof(BIGNUM *));
  if (!message_list) {
    log_message(LOG_FATAL, "message_list allocation failed\n");
    exit(EXIT_FAILURE);
  }

  for (unsigned int i = 0; i < BN_get_word(num_messages); i++) {
    message_list[i] = generate_big_message(message_size);
    if (!message_list[i]) {
      log_message(LOG_FATAL, "generate_big_message failed for message %u\n", i);
      // Free previously allocated BIGNUMs
      for (unsigned int j = 0; j < i; j++) {
        BN_free(message_list[j]);
      }
      free(message_list);
      exit(EXIT_FAILURE);
    }
  }
  
  log_message(LOG_INFO, "Message List Successfully generated");
  return message_list;
}

unsigned int bit_length(uint64_t num) {
  unsigned int length = 0;
  while (num > 0) {
    num >>= 1;
    length++;
  }
  return length == 0 ? 1 : length;
}