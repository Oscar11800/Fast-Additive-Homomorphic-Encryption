#include <openssl/bn.h>

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
  fahe2_key key;
  unsigned int msg_size;
  BIGNUM *num_additions;
} fahe2;

fahe2_key fahe2_keygen(int lambda, int m_max, int alpha);

// Function pointer type definition for fahe_enc
typedef BIGNUM (*fahe_enc_func)(int *enc_key, int message);

BIGNUM fahe2_enc(int *enc_key, int message);
BIGNUM *fahe2_enc_list(fahe_enc_func enc_func, int *message_list,
                       size_t list_size, int *enc_key);

int fahe2_dec(int *dec_key, BIGNUM ciphertext);