#include <math.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

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

BIGNUM *generate_big_message(unsigned int message_size) {
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

// TODO: This method does not work
// // Function to generate a random uint64_t number with n bits
// uint64_t generate_rand_int(unsigned int n) {
//     if (n > 64) {
//         fprintf(stderr, "Number of bits should be <= 64\n");
//         exit(EXIT_FAILURE);
//     }

//     // Calculate the number of bytes needed and maximum value for n bits
//     unsigned int bytes_needed = (n + 7) / 8;
//     uint64_t max_value = (1ULL << n) - 1;
//     uint64_t random_value = 0;
//     unsigned char buf[8] = {0};

//     // Generate random bytes
//     if (RAND_bytes(buf, bytes_needed) != 1) {
//         fprintf(stderr, "Error generating random bytes\n");
//         exit(EXIT_FAILURE);
//     }

//     // Convert bytes to uint64_t
//     for (unsigned int i = 0; i < bytes_needed; ++i) {
//         random_value = (random_value << 8) | buf[i];
//     }

//     // Ensure the value is within the correct range
//     random_value = random_value & max_value;
//     return random_value;
// }

BIGNUM **generate_message_list(unsigned int message_size,
                               unsigned int num_messages) {
  BIGNUM **message_list = (BIGNUM **)malloc(num_messages * sizeof(BIGNUM *));
  if (!message_list) {
    fprintf(stderr, "message_list allocation failed\n");
    exit(EXIT_FAILURE);
  }

  for (unsigned int i = 0; i < num_messages; i++) {
    message_list[i] = generate_big_message(message_size);
    if (!message_list[i]) {
      fprintf(stderr, "generate_big_message failed for message %u\n", i);
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