#include <openssl/bn.h>

BIGNUM *rand_num_below(const BIGNUM *upper_bound);
BIGNUM *rand_bits_below(unsigned int bitlength);
BIGNUM generate_message(unsigned int message_size);
uint64_t generate_int_message(unsigned int bit_length);
BIGNUM *generate_message_list(unsigned int message_size, unsigned int num_messages);
unsigned int bit_length(uint64_t num);