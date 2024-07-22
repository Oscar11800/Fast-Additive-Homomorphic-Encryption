
#include <openssl/bn.h>

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
  fahe1_key key;
  unsigned int msg_size;
  BIGNUM *num_additions;
} fahe1;

// // Enum to specify the type of instance
// typedef enum { FAHE1_TYPE, FAHE2_TYPE } fahe_type;

fahe1 *fahe1_init(const fahe_params *params);

void fahe1_free(fahe1 *fahe1_instance);

// Key generation function prototypes
fahe1_key fahe1_keygen(int lambda, int m_max, int alpha);

// Function pointer type definition for fahe_enc
typedef BIGNUM (*fahe_enc_func)(int *enc_key, int message);

// Encryption and decryption function prototypes
BIGNUM *fahe1_enc(BIGNUM *p, BIGNUM *X, int rho, int alpha, BIGNUM *message);
BIGNUM *fahe1_enc_list(fahe_enc_func enc_func, int *message_list,
                       size_t list_size, int *enc_key);

BIGNUM *fahe1_dec(BIGNUM *p, int m_max, int rho, int alpha, BIGNUM *ciphertext);