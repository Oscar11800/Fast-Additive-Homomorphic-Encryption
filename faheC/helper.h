#include <openssl/bn.h>

BIGNUM *rand_num_below(const BIGNUM *upper_bound);
BIGNUM *rand_bits_below(unsigned int bitlength);
BIGNUM *generate_big_message(unsigned int message_size);
uint64_t generate_random_uint64(uint64_t max_value);
uint64_t generate_rand_int(unsigned int n);
BIGNUM *generate_message_list(unsigned int message_size, unsigned int num_messages);
unsigned int bit_length(uint64_t num);