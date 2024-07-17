#include <gmp.h>
#include <math.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  int lambda_param;
  int m_max;
  int alpha;
  int msg_size;
} fahe_params;

typedef struct {
  int lambda_param;
  int m_max;
  int alpha;
  int msg_size;
  int *key;
  int *enc_key;
  int *dec_key;
} fahe_base;

typedef struct {
  fahe_base base;
  BIGNUM *num_additions;
} fahe1;

typedef struct {
  fahe_base base;
  BIGNUM *num_additions;
} fahe2;

// Union to hold either fahe1 or fahe2
typedef union {
  fahe1 fahe1_instance;
  fahe2 fahe2_instance;
} fahe_union;

// Enum to specify the type of instance
typedef enum { FAHE1_TYPE, FAHE2_TYPE } fahe_type;

void init();

// Function prototypes for initialization and cleanup
fahe_union *fahe_init(const fahe_params *params, fahe_type type);
void fahe_free(fahe_union *fahe, fahe_type type);

// Key generation function prototypes
int *fahe1_keygen(int lambda_param, int m_max, int alpha);
int *fahe2_keygen(int lambda_param, int m_max, int alpha);

// Function pointer type definition for fahe_enc
typedef BIGNUM (*fahe_enc_func)(int *enc_key, int message);

// Encryption and decryption function prototypes
BIGNUM fahe1_enc(int *enc_key, int message);
BIGNUM *fahe1_enc_list(fahe_enc_func enc_func, int *message_list, size_t list_size, int *enc_key);
BIGNUM fahe2_enc(int *enc_key, int message);
BIGNUM *fahe2_enc_list(fahe_enc_func enc_func, int *message_list, size_t list_size, int *enc_key);
int fahe1_dec(int *dec_key, BIGNUM ciphertext);
int fahe2_dec(int *dec_key, BIGNUM ciphertext);