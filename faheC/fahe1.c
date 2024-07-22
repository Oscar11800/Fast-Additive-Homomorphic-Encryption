#include "fahe1.h"

#include <math.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "helper.h"

#include <logger.h>

fahe1 *fahe1_init(const fahe_params *params) {
  fahe1 *fahe1_instance = (fahe1 *)malloc(sizeof(fahe1));
  if (!fahe1_instance) {
    log_message(LEVEL_FATAL, "Memory allocation for fahe_union struct failed\n");
    exit(EXIT_FAILURE);
  }

  printf("Debug: Memory allocated for fahe1_instance\n");

  // Generate the key
  fahe1_instance->key =
      fahe1_keygen(params->lambda, params->m_max, params->alpha);
  fahe1_instance->msg_size = params->msg_size;

  // Initialize num_additions for fahe1
  fahe1_instance->num_additions = BN_new();
  if (!fahe1_instance->num_additions) {
    log_message(LEVEL_FATAL, "Memory allocation for BIGNUM failed\n");
    free(fahe1_instance);
    exit(EXIT_FAILURE);
  }
  BN_one(fahe1_instance->num_additions);
  BN_lshift(fahe1_instance->num_additions, fahe1_instance->num_additions,
            (fahe1_instance->key.alpha) - 1);

  log_message(LEVEL_DEBUG,"Debug: fahe1_instance initialized\n");

  return fahe1_instance;
}

void fahe1_free(fahe1 *fahe1_instance) {
  if (!fahe1_instance) {
    log_message(LEVEL_ERROR, "No fahe1 to release.");
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
  log_message(LEVEL_INFO, "GAMMA: %d\n", gamma);

  // Generate a large prime p
  key.p = BN_new();
  if (!key.p) {
    log_message(LEVEL_ERROR, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }
  if (!BN_generate_prime_ex(key.p, (int)eta, 1, NULL, NULL, NULL)) {
    log_message(LEVEL_ERROR, "BN_generate_prime_ex failed\n");
    BN_free(key.p);
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_WARNING,"p decimal: %s\n", BN_bn2dec(key.p));

  // Calculate X = (2^gamma) / p using BIGNUM
  BIGNUM *X = BN_new();
  BIGNUM *base = BN_new();
  BIGNUM *gamma_bn = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!X || !base || !gamma_bn || !ctx) {
    log_message(LEVEL_ERROR, "BN_new or BN_CTX_new failed\n");
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
    log_message(LEVEL_ERROR, "BN_exp failed\n");
    BN_free(key.p);
    BN_free(X);
    BN_free(base);
    BN_free(gamma_bn);
    BN_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // Divide 2^gamma by p
  if (!BN_div(X, NULL, X, key.p, ctx)) {
    log_message(LEVEL_ERROR, "BN_div failed\n");
    BN_free(key.p);
    BN_free(X);
    BN_free(base);
    BN_free(gamma_bn);
    BN_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // Set X in the key structure
  key.X = X;

  // Clean up
  BN_free(base);
  BN_free(gamma_bn);
  BN_CTX_free(ctx);

  log_message(LEVEL_DEBUG, "Debug: Key generated\n");

  return key;
}

BIGNUM *fahe1_enc(BIGNUM *p, BIGNUM *X, int rho, int alpha, BIGNUM *message) {
  // Initialize BIGNUM values
  BIGNUM *q = NULL;
  BIGNUM *noise = NULL;
  BIGNUM *M = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *rho_alpha_shift = BN_new();
  BIGNUM *rho_alpha = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!M || !n || !c || !rho_alpha_shift || !rho_alpha || !ctx) {
    log_message(LEVEL_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  log_message(LEVEL_DEBUG, "Debug: Initialized BIGNUM variables\n");

  // q < X + 1
  BIGNUM *X_plus_one = BN_new();
  if (!X_plus_one) {
    log_message(LEVEL_ERROR, "BN_new for X_plus_one failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: BN_new for X_plus_one succeeded\n");

  if (!X) {
    log_message(LEVEL_ERROR, "Input BIGNUM X is NULL\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: Input BIGNUM X is not NULL\n");

  log_message(LEVEL_DEBUG, "Debug: X = ");
  BN_print_fp(stderr, X);
  log_message(LEVEL_DEBUG, "\n");

  if (!BN_copy(X_plus_one, X)) {
    log_message(LEVEL_ERROR, "BN_copy failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: BN_copy succeeded\n");

  if (!BN_add_word(X_plus_one, 1)) {
    log_message(LEVEL_ERROR, "BN_add_word failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: BN_add_word succeeded\n");

  log_message(LEVEL_DEBUG, "Debug: X + 1 = ");
  BN_print_fp(stderr, X_plus_one);
  log_message(LEVEL_DEBUG, "\n");

  q = rand_num_below(X_plus_one);
  if (!q) {
    log_message(LEVEL_ERROR, "rand_num_below failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: q = ");
  BN_print_fp(stderr, q);
  log_message(LEVEL_DEBUG, "\n");
  BN_free(X_plus_one);

  // Generate random noise of bit length rho
  noise = rand_bits_below(rho);
  if (!noise) {
    log_message(LEVEL_ERROR, "rand_bits_below failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: noise = ");
  BN_print_fp(stderr, noise);
  log_message(LEVEL_DEBUG, "\n");

  // M = (message << (rho + alpha)) + noise
  if (!BN_set_word(rho_alpha, rho + alpha)) {
    log_message(LEVEL_ERROR, "BN_set_word failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: rho + alpha = ");
  BN_print_fp(stderr, rho_alpha);
  log_message(LEVEL_DEBUG, "\n");

  if (!BN_lshift(rho_alpha_shift, message, rho + alpha)) {
    log_message(LEVEL_ERROR, "BN_lshift failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: message << (rho + alpha) = ");
  BN_print_fp(stderr, rho_alpha_shift);
  log_message(LEVEL_DEBUG, "\n");

  if (!BN_add(M, rho_alpha_shift, noise)) {
    log_message(LEVEL_ERROR, "BN_add for M failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: M = ");
  BN_print_fp(stderr, M);
  log_message(LEVEL_DEBUG, "\n");

  // n = p * q
  if (!BN_mul(n, p, q, ctx)) {
    log_message(LEVEL_ERROR, "BN_mul failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: n = ");
  BN_print_fp(stderr, n);
  log_message(LEVEL_DEBUG, "\n");

  // c = n + M
  if (!BN_add(c, n, M)) {
    log_message(LEVEL_ERROR, "BN_add for c failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: c = ");
  BN_print_fp(stderr, c);
  log_message(LEVEL_DEBUG, "\n");

  // Free temporary BIGNUMs and context
  BN_free(q);
  BN_free(noise);
  BN_free(M);
  BN_free(n);
  BN_free(rho_alpha_shift);
  BN_free(rho_alpha);
  BN_CTX_free(ctx);

  return c;
}

BIGNUM *fahe1_dec(BIGNUM *p, int m_max, int rho, int alpha,
                  BIGNUM *ciphertext) {
  BIGNUM *m_full = BN_new();
  BIGNUM *m_shifted = BN_new();
  BIGNUM *m_masked = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!m_full || !m_shifted || !m_masked || !ctx) {
    log_message(LEVEL_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  // m_full = ciphertext % p
  if (!BN_mod(m_full, ciphertext, p, ctx)) {
    log_message(LEVEL_ERROR, "BN_mod failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: m_full = ");
  BN_print_fp(stderr, m_full);
  log_message(LEVEL_DEBUG, "\n");

  // m_shifted = m_full >> (rho + alpha)
  if (!BN_rshift(m_shifted, m_full, rho + alpha)) {
    log_message(LEVEL_ERROR, "BN_rshift failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: m_shifted before masking = ");
  BN_print_fp(stderr, m_shifted);
  log_message(LEVEL_DEBUG, "\n");

  // Mask the bits to the size of m_max
  if (!BN_mask_bits(m_shifted, m_max)) {
    log_message(LEVEL_ERROR, "BN_mask_bits failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: m_shifted after masking = ");
  BN_print_fp(stderr, m_shifted);
  log_message(LEVEL_DEBUG, "\n");

  // Assign the masked value to m_masked
  if (!BN_copy(m_masked, m_shifted)) {
    log_message(LEVEL_ERROR, "BN_copy failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LEVEL_DEBUG, "Debug: m_masked after copying = ");
  BN_print_fp(stderr, m_masked);
  log_message(LEVEL_DEBUG, "\n");

  // Free allocated memory
  BN_free(m_full);
  BN_free(m_shifted);
  BN_CTX_free(ctx);

  return m_masked;
}