#include <math.h>
#include <openssl/bn.h>

BIGNUM *rand_num_below(const BIGNUM *upper_bound) {
  BIGNUM *rand_bn = BN_new();
  if (!rand_bn) {
    fprintf(stderr, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }

  if (!BN_rand_range(rand_bn, upper_bound)) {
    fprintf(stderr, "BN_rand_range failed\n");
    BN_free(rand_bn);
    exit(EXIT_FAILURE);
  }

  return rand_bn;
}

BIGNUM *rand_bits_below(unsigned int bitlength) {
  BIGNUM *rand_bn = BN_new();
  if (!rand_bn) {
    fprintf(stderr, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }

  if (!BN_rand(rand_bn, bitlength, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
    fprintf(stderr, "BN_rand failed\n");
    BN_free(rand_bn);
    exit(EXIT_FAILURE);
  }

  // Ensure the generated number is positive
  if (BN_is_negative(rand_bn)) {
    BN_set_negative(rand_bn, 0);
  }

  return rand_bn;
}

BIGNUM *generate_message(unsigned int message_size) {
  BIGNUM *BN_message = BN_new();
  if (!BN_message) {
    fprintf(stderr, "BNmessage failed\n");
    BN_free(BN_message);
    exit(EXIT_FAILURE);
  }

  // Generate a random number of `message_size` bits
  if (!BN_rand(BN_message, message_size, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
    fprintf(stderr, "BNmessage failed\n");
    BN_free(BN_message);
    exit(EXIT_FAILURE);
  }

  return BN_message;
}

uint64_t generate_int_message(unsigned int bit_length) {
  if (bit_length > 64) {
    fprintf(stderr, "Bit length must be 64 or less\n");
    exit(EXIT_FAILURE);
  }
  // Calculate the maximum value for the given bit length
  uint64_t max_value = (1ULL << bit_length) - 1;
  // Generate a random number in the range [0, max_value]
  uint64_t random_value = 0;
  for (unsigned int i = 0; i < bit_length; i += 32) {
    random_value <<= 32;
    random_value |= (uint32_t)rand();
  }
  // Ensure the number is within the desired bit length
  random_value &= max_value;

  return random_value;
}

BIGNUM **generate_message_list(unsigned int message_size,
                               unsigned int num_messages) {
  BIGNUM **message_list = (BIGNUM **)malloc(num_messages * sizeof(BIGNUM *));
  if (!message_list) {
    fprintf(stderr, "message_list allocation failed\n");
    exit(EXIT_FAILURE);
  }

  for (unsigned int i = 0; i < num_messages; i++) {
    message_list[i] = generate_message(message_size);
    if (!message_list[i]) {
      fprintf(stderr, "generate_message failed for message %u\n", i);
      // Free previously allocated BIGNUMs
      for (unsigned int j = 0; j < i; j++) {
        BN_free(message_list[j]);
      }
      free(message_list);
      exit(EXIT_FAILURE);
    }
  }

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