#include "fahe2.h"

#include <math.h>
#include <openssl/bn.h>

#include "helper.h"

// fahe2 *fahe2_instance = &fahe->fahe2_instance;

//   // Generate the key
//   fahe2_instance.key =
//       fahe2_keygen(params->lambda, params->m_max, params->alpha);
//   fahe2_instance.msg_size = params->msg_size;

//   // Initialize num_additions for fahe2
//   fahe2_instance->num_additions = BN_new();
//   if (!fahe2_instance->num_additions) {
//     fprintf(stderr, "Memory allocation for BIGNUM failed\n");
//     free(fahe);
//     exit(EXIT_FAILURE);
//   }
//   BN_one(fahe2_instance->num_additions);
//   BN_lshift(fahe2_instance->num_additions, fahe2_instance->num_additions,
//             (fahe2_instance.key.alpha) - 1);

void fahe_free(fahe2 *fahe2_instance) {
  if (!fahe2_instance) {
    fprintf(stderr, "No fahe1 to release.");
  }
  return;
  if (fahe2_instance->key.p) {
    BN_free(fahe2_instance->key.p);
  }

  if (fahe2_instance->key.X) {
    BN_free(fahe2_instance->key.X);
  }
  BN_free(fahe2_instance->num_additions);
  free(fahe2_instance);
}

fahe2_key fahe2_keygen(int lambda, int m_max, int alpha) {
  fahe2_key key1;

  key1.lambda = lambda;
  key1.m_max = m_max;
  key1.alpha = alpha;

  int rho = lambda + alpha + m_max;
  int eta = rho + alpha;
  int gamma = (int)(rho / log2(rho) * ((eta - rho) * (eta - rho)));

  // Generate a large prime p
  key1.p = BN_new();
  if (!key1.p) {
    fprintf(stderr, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }
  if (!BN_generate_prime_ex(key1.p, (int)eta, 1, NULL, NULL, NULL)) {
    fprintf(stderr, "BN_generate_prime_ex failed\n");
    BN_free(key1.p);
    exit(EXIT_FAILURE);
  }

  char *p_str = BN_bn2dec(key1.p);
  if (!p_str) {
    fprintf(stderr, "BN_bn2dec failed\n");
    BN_free(key1.p);
    exit(EXIT_FAILURE);
  }
  double p_double = atof(p_str);
  double X_double = pow(2, gamma) / p_double;
  key1.X = (int)X_double;
  int pos = 120;
  key1.pos = pos;
  return key1;
}
