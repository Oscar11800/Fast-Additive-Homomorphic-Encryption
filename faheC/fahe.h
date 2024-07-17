#include <math.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  int lambda;
  int m_max;
  int alpha;
  int msg_size;
} fahe_params;

typedef struct {
  int lambda;
  int m_max;
  int alpha;
  int rho;
  BIGNUM *X;
  BIGNUM *p;
} fahe1_key;

typedef struct {
  int lambda;
  int m_max;
  int alpha;
  int X;
  int rho;
  int pos;
  BIGNUM *p;

} fahe2_key;

typedef struct {
  fahe1_key key1;  // Encapsulated key
  fahe2_key key2;
  int *enc_key;
  int *dec_key;
  int msg_size;
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
fahe1_key fahe1_keygen(int lambda, int m_max, int alpha);
fahe2_key fahe2_keygen(int lambda, int m_max, int alpha);

// Function pointer type definition for fahe_enc
typedef BIGNUM (*fahe_enc_func)(int *enc_key, int message);

// Encryption and decryption function prototypes
BIGNUM fahe1_enc(int *enc_key, int message);
BIGNUM *fahe1_enc_list(fahe_enc_func enc_func, int *message_list,
                       size_t list_size, int *enc_key);
BIGNUM fahe2_enc(int *enc_key, int message);
BIGNUM *fahe2_enc_list(fahe_enc_func enc_func, int *message_list,
                       size_t list_size, int *enc_key);
int fahe1_dec(int *dec_key, BIGNUM ciphertext);
int fahe2_dec(int *dec_key, BIGNUM ciphertext);