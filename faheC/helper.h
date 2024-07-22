#include <openssl/bn.h>

BIGNUM *rand_num_below(const BIGNUM *upper_bound);
BIGNUM *rand_bits_below(unsigned int bitlength);
BIGNUM *generate_big_message(unsigned int message_size);
uint64_t generate_random_uint64(uint64_t max_value);
uint64_t generate_rand_int(unsigned int n);
BIGNUM **generate_message_list(unsigned int message_size, BIGNUM *num_messages);
unsigned int bit_length(uint64_t num);
void write_messages_to_file(BIGNUM **message_list, unsigned int num_msgs,
                            const char *filename);
void print_bn_list(const char *label, BIGNUM **bn_list, unsigned int len);
void print_bn(const char *label, BIGNUM *bn);
void debug_fahe1_init(fahe1 *fahe1_instance);