#include "fahe1.h"

#include <math.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "helper.h"

fahe1 *fahe1_init(const fahe_params *params) {
  fahe1 *fahe1_instance = (fahe1 *)malloc(sizeof(fahe1));
  if (!fahe1_instance) {
    fprintf(stderr, "Memory allocation for fahe_union struct failed\n");
    exit(EXIT_FAILURE);
  }
  // Generate the key
  fahe1_instance->key =
      fahe1_keygen(params->lambda, params->m_max, params->alpha);
  fahe1_instance->msg_size = params->msg_size;

  // Initialize num_additions for fahe1
  fahe1_instance->num_additions = BN_new();
  if (!fahe1_instance->num_additions) {
    fprintf(stderr, "Memory allocation for BIGNUM failed\n");
    free(fahe1_instance);
    exit(EXIT_FAILURE);
  }
  BN_one(fahe1_instance->num_additions);
  BN_lshift(fahe1_instance->num_additions, fahe1_instance->num_additions,
            (fahe1_instance->key.alpha) - 1);
  return fahe1_instance;
}

void fahe1_free(fahe1 *fahe1_instance) {
  if (!fahe1_instance) {
    fprintf(stderr, "No fahe1 to release.");
  }
  return;
  if (fahe1_instance->key.p) {
    BN_free(fahe1_instance->key.p);
  }

  if (fahe1_instance->key.X) {
    BN_free(fahe1_instance->key.X);
  }
  BN_free(fahe1_instance->num_additions);
  free(fahe1_instance);
}

fahe1_key fahe1_keygen(int lambda, int m_max, int alpha) {
  fahe1_key key;

  key.lambda = lambda;
  key.m_max = m_max;
  key.alpha = alpha;

  int rho = lambda;
  key.rho = rho;
  double eta = rho + (2 * alpha) + m_max;
  int gamma = (int)(rho / log2(rho) * ((eta - rho) * (eta - rho)));
  fprintf(stdout, "GAMMA: %d", gamma);
  // Generate a large prime p
  key.p = BN_new();
  if (!key.p) {
    fprintf(stderr, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }
  if (!BN_generate_prime_ex(key.p, (int)eta, 1, NULL, NULL, NULL)) {
    fprintf(stderr, "BN_generate_prime_ex failed\n");
    BN_free(key.p);
    exit(EXIT_FAILURE);
  }
  printf("p decimal: %s\n", BN_bn2dec(key.p));

  // Calculate X = (2^gamma) / p using BIGNUM
  BIGNUM *X = BN_new();
  BIGNUM *base = BN_new();
  BIGNUM *gamma_bn = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!X || !base || !gamma_bn || !ctx) {
    fprintf(stderr, "BN_new or BN_CTX_new failed\n");
    BN_free(key.p);
    BN_free(X);
    BN_free(base);
    BN_free(gamma_bn);
    BN_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  BN_set_word(base, 2);
  BN_set_word(gamma_bn, gamma);

  // Calculate 2^gamma
  if (!BN_exp(X, base, gamma_bn, ctx)) {
    fprintf(stderr, "BN_exp failed\n");
    BN_free(key.p);
    BN_free(X);
    BN_free(base);
    BN_free(gamma_bn);
    BN_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // Divide 2^gamma by p
  if (!BN_div(X, NULL, X, key.p, ctx)) {
    fprintf(stderr, "BN_div failed\n");
    BN_free(key.p);
    BN_free(X);
    BN_free(base);
    BN_free(gamma_bn);
    BN_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // Convert X to int
  key.X = X;

  // Clean up
  BN_free(X);
  BN_free(base);
  BN_free(gamma_bn);
  BN_CTX_free(ctx);

  return key;
}

BIGNUM *fahe1_enc(BIGNUM *p, BIGNUM *X, int rho, int alpha, int message) {
  printf("ENCRYPTING");
  BIGNUM *q = NULL;
  BIGNUM *noise = NULL;
  BIGNUM *M = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *message_bn = BN_new();
  BIGNUM *rho_alpha_shift = BN_new();
  BIGNUM *rho_alpha = BN_new();
  //   CTX stores temp variables
  BN_CTX *ctx = BN_CTX_new();

  if (!M || !n || !c || !message_bn || !rho_alpha_shift || !rho_alpha || !ctx) {
    fprintf(stderr, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  // Generate q < X + 1
  BIGNUM *X_plus_one = BN_new();
  if (!X_plus_one) {
    fprintf(stderr, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }
  BN_copy(X_plus_one, X);
  BN_add_word(X_plus_one, 1);
  q = rand_num_below(X_plus_one);
  BN_free(X_plus_one);

  // TODO: Can noise be negative?
  // Generate random noise of bit length rho
  noise = rand_bits_below(rho);
  printf("Noise: %s", BN_bn2dec(noise));

  // M = (message << (rho + alpha)) + noise
  BN_set_word(message_bn, message);
  BN_set_word(rho_alpha, rho + alpha);
  BN_lshift(rho_alpha_shift, message_bn, rho + alpha);
  BN_add(M, rho_alpha_shift, noise);

  // n = p * q
  BN_mul(n, p, q, ctx);

  // c = n + M
  BN_add(c, n, M);

  // Free temporary BIGNUMs and context
  BN_free(q);
  BN_free(noise);
  BN_free(M);
  BN_free(n);
  BN_free(message_bn);
  BN_free(rho_alpha_shift);
  BN_free(rho_alpha);
  BN_CTX_free(ctx);

  return c;
}