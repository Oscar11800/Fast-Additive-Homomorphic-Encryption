#include <openssl/bn.h>
#include "fahe2.h"

BIGNUM *rand_bignum_below(const BIGNUM *upper_bound);
int rand_int_below(int x);
BIGNUM *rand_bits_below(unsigned int bitlength);
BIGNUM *generate_big_message(unsigned int message_size);
BIGNUM **generate_message_list(unsigned int message_size, BIGNUM *num_messages);
void free_message_list(BIGNUM **message_list, int list_size);
unsigned int bit_length(uint64_t num);
void write_messages_to_file(BIGNUM **message_list, unsigned int num_msgs,
                            const char *filename);
void print_bn_list(const char *label, BIGNUM **bn_list, unsigned int len);
void print_bn(const char *label, BIGNUM *bn);
void debug_fahe1_init(fahe1 *fahe1_instance);
void debug_fahe2_init(fahe2 *fahe2_instance);
BIGNUM **read_bignum_list_from_file(const char *filename, int *num_elements);
void print_test_table(char *test_name, fahe_params params, int num_trials,
                      double avg_keygen_time, double avg_encryption_time,
                      double avg_decryption_time, double total_keygen_time,
                      double total_encryption_time,
                      double total_decryption_time);