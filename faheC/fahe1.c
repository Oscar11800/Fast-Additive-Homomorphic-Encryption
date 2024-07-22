#include "fahe1.h"

#include <math.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "helper.h"
#include "logger.h"

fahe1 *fahe1_init(const fahe_params *params) {
  log_message(LOG_INFO, "Fahe1 init start...\n");
  fahe1 *fahe1_instance = (fahe1 *)malloc(sizeof(fahe1));
#ifdef ENABLE_MEMORY_CHECKS
  if (!fahe1_instance) {
    log_message(LOG_FATAL, "Memory allocation for fahe_union struct failed\n");
    exit(EXIT_FAILURE);
  }
#endif

  log_message(LOG_DEBUG, "Memory allocated for fahe1_instance\n");

  // Generate the key
  fahe1_instance->key =
      fahe1_keygen(params->lambda, params->m_max, params->alpha);
  fahe1_instance->msg_size = params->msg_size;

  // Initialize num_additions for fahe1
  fahe1_instance->num_additions = BN_new();
#ifdef ENABLE_MEMORY_CHECKS
  if (!fahe1_instance->num_additions) {
    log_message(LOG_FATAL, "Memory allocation for BIGNUM failed\n");
    free(fahe1_instance);
    exit(EXIT_FAILURE);
  }
#endif
  BN_one(fahe1_instance->num_additions);
  BN_lshift(fahe1_instance->num_additions, fahe1_instance->num_additions,
            (fahe1_instance->key.alpha) - 1);

  log_message(LOG_DEBUG, "Debug: fahe1_instance initialized\n");

  return fahe1_instance;
}

void fahe1_free(fahe1 *fahe1_instance) {
#ifdef ENABLE_MEMORY_CHECKS
  if (!fahe1_instance) {
    log_message(LOG_ERROR, "No fahe1 to release.");
  }
#endif
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
  log_message(LOG_DEBUG, "GAMMA: %d\n", gamma);

  // Generate a large prime p
  key.p = BN_new();
  if (!key.p) {
    log_message(LOG_FATAL, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }
  if (!BN_generate_prime_ex(key.p, (int)eta, 1, NULL, NULL, NULL)) {
    log_message(LOG_FATAL, "BN_generate_prime_ex failed\n");
    BN_free(key.p);
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "p decimal: %s\n", BN_bn2dec(key.p));

  // Calculate X = (2^gamma) / p using BIGNUM
  BIGNUM *X = BN_new();
  BIGNUM *base = BN_new();
  BIGNUM *gamma_bn = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!X || !base || !gamma_bn || !ctx) {
    log_message(LOG_FATAL, "BN_new or BN_CTX_new failed\n");
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
    log_message(LOG_FATAL, "BN_exp failed\n");
    BN_free(key.p);
    BN_free(X);
    BN_free(base);
    BN_free(gamma_bn);
    BN_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // Divide 2^gamma by p
  if (!BN_div(X, NULL, X, key.p, ctx)) {
    log_message(LOG_FATAL, "BN_div failed\n");
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

  log_message(LOG_INFO, "Debug: FAHE1 Key generated...\n");

  return key;
}

BIGNUM *fahe1_enc(BIGNUM *p, BIGNUM *X, int rho, int alpha, BIGNUM *message) {
  log_message(LOG_DEBUG, "Initializing Encryption");
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
    log_message(LOG_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  log_message(LOG_DEBUG, "Debug: Initialized BIGNUM variables\n");

  // q < X + 1
  BIGNUM *X_plus_one = BN_new();
  if (!X_plus_one) {
    log_message(LOG_FATAL, "BN_new for X_plus_one failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: BN_new for X_plus_one succeeded\n");

  if (!X) {
    log_message(LOG_FATAL, "Input BIGNUM X is NULL\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: Input BIGNUM X is not NULL\n");

  log_message(LOG_DEBUG, "Debug: X = %c\n", BN_bn2dec(X));

  if (!BN_copy(X_plus_one, X)) {
    log_message(LOG_FATAL, "BN_copy failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: BN_copy succeeded\n");

  if (!BN_add_word(X_plus_one, 1)) {
    log_message(LOG_FATAL, "BN_add_word failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: BN_add_word succeeded\n");

  log_message(LOG_DEBUG, "Debug: X+1 = %c\n", BN_bn2dec(X_plus_one));

  q = rand_num_below(X_plus_one);
  if (!q) {
    log_message(LOG_FATAL, "rand_num_below failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: q = %c\n", BN_bn2dec(q));
  BN_free(X_plus_one);

  // Generate random noise of bit length rho
  noise = rand_bits_below(rho);
  if (!noise) {
    log_message(LOG_FATAL, "rand_bits_below failed\n");
    exit(EXIT_FAILURE);
  }

  log_message(LOG_DEBUG, "Debug: noise = %c\n", BN_bn2dec(noise));

  // M = (message << (rho + alpha)) + noise
  if (!BN_set_word(rho_alpha, rho + alpha)) {
    log_message(LOG_FATAL, "BN_set_word failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: rho+alpha = %c\n", BN_bn2dec(rho_alpha));

  if (!BN_lshift(rho_alpha_shift, message, rho + alpha)) {
    log_message(LOG_FATAL, "BN_lshift failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: message << (rho + alpha) = %c\n",
              BN_bn2dec(rho_alpha_shift));

  if (!BN_add(M, rho_alpha_shift, noise)) {
    log_message(LOG_FATAL, "BN_add for M failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: M = %c\n", BN_bn2dec(M));

  // n = p * q
  if (!BN_mul(n, p, q, ctx)) {
    log_message(LOG_FATAL, "BN_mul failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: n = %c\n", BN_bn2dec(n));

  // c = n + M
  if (!BN_add(c, n, M)) {
    log_message(LOG_FATAL, "BN_add for c failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: c = %c\n", BN_bn2dec(c));

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


BIGNUM **fahe1_enc_list(BIGNUM *p, BIGNUM *X, int rho, int alpha,
                        BIGNUM **message_list, BIGNUM *list_size) {
  // Initialize BIGNUM values
  BIGNUM *q = NULL;
  BIGNUM *noise = NULL;
  BIGNUM *M = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *rho_alpha_shift = BN_new();
  BIGNUM *rho_alpha = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM **ciphertext_list = malloc(BN_get_word(list_size) * sizeof(BIGNUM *));
#ifdef ENABLE_MEMORY_CHECKS
  if (ciphertext_list == NULL) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    return NULL;
  }

  if (!M || !n || !c || !rho_alpha_shift || !rho_alpha || !ctx) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }
#endif

  log_message(LOG_INFO, "Initialized BIGNUM variables\n");

  // q < X + 1
  BIGNUM *X_plus_one = BN_new();
#ifdef ENABLE_MEMORY_CHECKS
  if (!X_plus_one) {
    log_message(LOG_FATAL, "BN_new for X_plus_one failed\n");
    exit(EXIT_FAILURE);
  }
#endif

  log_message(LOG_DEBUG, "Debug: BN_new for X_plus_one succeeded\n");

#ifdef ENABLE_MEMORY_CHECKS
  if (!X) {
    log_message(LOG_FATAL, "Input BIGNUM X is NULL\n");
    exit(EXIT_FAILURE);
  }
#endif

  log_message(LOG_DEBUG, "Debug: Input BIGNUM X is not NULL\n");

  char *X_str = BN_bn2dec(X);
  log_message(LOG_DEBUG, "Debug: X = %s\n", X_str);
  OPENSSL_free(X_str);

#ifdef ENABLE_MEMORY_CHECKS
  if (!BN_copy(X_plus_one, X)) {
    log_message(LOG_FATAL, "BN_copy failed\n");
    exit(EXIT_FAILURE);
  }
#else
  BN_copy(X_plus_one, X);
#endif

  log_message(LOG_DEBUG, "Debug: BN_copy succeeded\n");

#ifdef ENABLE_MEMORY_CHECKS
  if (!BN_add_word(X_plus_one, 1)) {
    log_message(LOG_FATAL, "BN_add_word failed\n");
    exit(EXIT_FAILURE);
  }
#else
  BN_add_word(X_plus_one, 1);
#endif

  char *X_plus_one_str = BN_bn2dec(X_plus_one);
  log_message(LOG_DEBUG, "Debug: X + 1 = %s\n", X_plus_one_str);
  OPENSSL_free(X_plus_one_str);

  for (int i = 0; i < BN_get_word(list_size); i++) {
    q = rand_num_below(X_plus_one);

#ifdef ENABLE_MEMORY_CHECKS
    if (!q) {
      log_message(LOG_FATAL, "rand_num_below failed\n");
      exit(EXIT_FAILURE);
    }
#endif

    char *q_str = BN_bn2dec(q);
    log_message(LOG_DEBUG, "Debug: q = %s\n", q_str);
    OPENSSL_free(q_str);

    noise = rand_bits_below(rho);

#ifdef ENABLE_MEMORY_CHECKS
    if (!noise) {
      log_message(LOG_FATAL, "rand_bits_below failed\n");
      exit(EXIT_FAILURE);
    }
#endif

    char *noise_str = BN_bn2dec(noise);
    log_message(LOG_DEBUG, "Debug: noise = %s\n", noise_str);
    OPENSSL_free(noise_str);

#ifdef ENABLE_MEMORY_CHECKS
    if (!BN_set_word(rho_alpha, rho + alpha)) {
      log_message(LOG_FATAL, "BN_set_word failed\n");
      exit(EXIT_FAILURE);
    }
#else
    BN_set_word(rho_alpha, rho + alpha);
#endif

    char *rho_alpha_str = BN_bn2dec(rho_alpha);
    log_message(LOG_DEBUG, "Debug: rho + alpha = %s\n", rho_alpha_str);
    OPENSSL_free(rho_alpha_str);

    ciphertext_list[i] = BN_new();
#ifdef ENABLE_MEMORY_CHECKS
    if (!ciphertext_list[i]) {
      log_message(LOG_FATAL, "BN_new failed for index %d\n", i);
      for (int j = 0; j < i; j++) {
        BN_free(ciphertext_list[j]);
      }
      free(ciphertext_list);
      exit(EXIT_FAILURE);
    }
#endif

#ifdef ENABLE_MEMORY_CHECKS
    if (!BN_lshift(rho_alpha_shift, message_list[i], rho + alpha)) {
      log_message(LOG_FATAL, "BN_lshift failed\n");
      for (int j = 0; j <= i; j++) {
        BN_free(ciphertext_list[j]);
      }
      free(ciphertext_list);
      exit(EXIT_FAILURE);
    }
#else
    BN_lshift(rho_alpha_shift, message_list[i], rho + alpha);
#endif

    char *rho_alpha_shift_str = BN_bn2dec(rho_alpha_shift);
    log_message(LOG_DEBUG, "Debug: message << (rho + alpha) = %s\n", rho_alpha_shift_str);
    OPENSSL_free(rho_alpha_shift_str);

#ifdef ENABLE_MEMORY_CHECKS
    if (!BN_add(M, rho_alpha_shift, noise)) {
      log_message(LOG_FATAL, "BN_add for M failed\n");
      exit(EXIT_FAILURE);
    }
#else
    BN_add(M, rho_alpha_shift, noise);
#endif

    char *M_str = BN_bn2dec(M);
    log_message(LOG_DEBUG, "Debug: M = %s\n", M_str);
    OPENSSL_free(M_str);

#ifdef ENABLE_MEMORY_CHECKS
    if (!BN_mul(n, p, q, ctx)) {
      log_message(LOG_FATAL, "BN_mul failed\n");
      exit(EXIT_FAILURE);
    }
#else
    BN_mul(n, p, q, ctx);
#endif

    char *n_str = BN_bn2dec(n);
    log_message(LOG_DEBUG, "Debug: n = %s\n", n_str);
    OPENSSL_free(n_str);

#ifdef ENABLE_MEMORY_CHECKS
    if (!BN_add(c, n, M)) {
      log_message(LOG_FATAL, "BN_add for c failed\n");
      exit(EXIT_FAILURE);
    }
#else
    BN_add(c, n, M);
#endif

    char *c_str = BN_bn2dec(c);
    log_message(LOG_DEBUG, "Debug: c = %s\n", c_str);
    OPENSSL_free(c_str);

#ifdef ENABLE_MEMORY_CHECKS
    if (!BN_copy(ciphertext_list[i], c)) {
      log_message(LOG_FATAL, "BN_copy failed for ciphertext_list[%d]\n", i);
      exit(EXIT_FAILURE);
    }
#else
    BN_copy(ciphertext_list[i], c);
#endif
  }

  // Free temporary BIGNUMs and context
  BN_free(X_plus_one);
  BN_free(M);
  BN_free(n);
  BN_free(c);
  BN_free(rho_alpha_shift);
  BN_free(rho_alpha);
  BN_CTX_free(ctx);

  return ciphertext_list;
}

BIGNUM *fahe1_dec(BIGNUM *p, int m_max, int rho, int alpha,
                  BIGNUM *ciphertext) {
  BIGNUM *m_full = BN_new();
  BIGNUM *m_shifted = BN_new();
  BIGNUM *m_masked = BN_new();
  BN_CTX *ctx = BN_CTX_new();

#ifdef ENABLE_MEMORY_CHECKS
  if (!m_full || !m_shifted || !m_masked || !ctx) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }
#endif

// m_full = ciphertext % p
#ifdef ENABLE_MEMORY_CHECKS
  if (!BN_mod(m_full, ciphertext, p, ctx)) {
    log_message(LOG_FATAL, "BN_mod failed\n");
    exit(EXIT_FAILURE);
  }
#else
  BN_mod(m_full, ciphertext, p, ctx);
#endif

  log_message(LOG_DEBUG, "Debug: m_full = %c\n", BN_bn2dec(m_full));

// m_shifted = m_full >> (rho + alpha)
#ifdef ENABLE_MEMORY_CHECKS
  if (!BN_rshift(m_shifted, m_full, rho + alpha)) {
    log_message(LOG_FATAL, "BN_rshift failed\n");
    exit(EXIT_FAILURE);
  }
#else
  BN_rshift(m_shifted, m_full, rho + alpha);
#endif

  log_message(LOG_DEBUG, "Debug:  m_shifted before masking = %c\n",
              BN_bn2dec(m_shifted));

// Mask the bits to the size of m_max
#ifdef ENABLE_MEMORY_CHECKS
  if (!BN_mask_bits(m_shifted, m_max)) {
    log_message(LOG_FATAL, "BN_mask_bits failed\n");
    exit(EXIT_FAILURE);
  }
#else
  BN_mask_bits(m_shifted, m_max);
#endif
  log_message(LOG_DEBUG, "Debug:  m_shifted after masking = %c\n",
              BN_bn2dec(m_masked));

// Assign the masked value to m_masked
#ifdef ENABLE_MEMORY_CHECKS
  if (!BN_copy(m_masked, m_shifted)) {
    log_message(LOG_FATAL, "BN_copy failed\n");
    exit(EXIT_FAILURE);
  }
#else
  BN_copy(m_masked, m_shifted);
#endif
  log_message(LOG_DEBUG, "Debug: m_masked after copying = %c\n",
              BN_bn2dec(m_masked));

  // Free allocated memory
  BN_free(m_full);
  BN_free(m_shifted);
  BN_CTX_free(ctx);

  return m_masked;
}

BIGNUM **fahe1_dec_list(BIGNUM *p, int m_max, int rho, int alpha,
                        BIGNUM **ciphertext_list, BIGNUM *list_size) {
  // Initialize BIGNUM values
  BIGNUM *m_full = BN_new();
  BIGNUM *m_shifted = BN_new();
  BN_CTX *ctx = BN_CTX_new();

#ifdef ENABLE_MEMORY_CHECKS
  if (!m_full || !m_shifted || !ctx) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }
#endif

  // Allocate memory for the list of decrypted messages
  BIGNUM **decrypted_list = malloc(BN_get_word(list_size) * sizeof(BIGNUM *));
#ifdef ENABLE_MEMORY_CHECKS
  if (decrypted_list == NULL) {
    log_message(LOG_FATAL, "Memory allocation for decrypted_list failed\n");
    BN_free(m_full);
    BN_free(m_shifted);
    BN_CTX_free(ctx);
    return NULL;
  }
#endif

  // Decrypt each ciphertext
  for (size_t i = 0; i < BN_get_word(list_size); i++) {
    // Allocate memory for each decrypted message
    decrypted_list[i] = BN_new();
#ifdef ENABLE_MEMORY_CHECKS
    if (!decrypted_list[i]) {
      log_message(LOG_FATAL, "BN_new failed for index %zu\n", i);
      //  Free already allocated BIGNUMs
      for (size_t j = 0; j < i; j++) {
        BN_free(decrypted_list[j]);
      }
      free(decrypted_list);
      BN_free(m_full);
      BN_free(m_shifted);
      BN_CTX_free(ctx);
      return NULL;
    }
#endif

// m_full = ciphertext % p
#ifdef ENABLE_MEMORY_CHECKS
    if (!BN_mod(m_full, ciphertext_list[i], p, ctx)) {
      log_message(LOG_FATAL, "BN_mod failed for index %zu\n", i);
      BN_free(decrypted_list[i]);
      // Free already allocated BIGNUMs
      for (size_t j = 0; j < i; j++) {
        BN_free(decrypted_list[j]);
      }
      free(decrypted_list);
      BN_free(m_full);
      BN_free(m_shifted);
      BN_CTX_free(ctx);
      return NULL;
    }
#else
    BN_mod(m_full, ciphertext_list[i], p, ctx);
#endif

// m_shifted = m_full >> (rho + alpha)
#ifdef ENABLE_MEMORY_CHECKS
    if (!BN_rshift(m_shifted, m_full, rho + alpha)) {
      log_message(LOG_FATAL, "BN_rshift failed for index %zu\n", i);
      BN_free(decrypted_list[i]);
      // Free already allocated BIGNUMs
      for (size_t j = 0; j < i; j++) {
        BN_free(decrypted_list[j]);
      }
      free(decrypted_list);
      BN_free(m_full);
      BN_free(m_shifted);
      BN_CTX_free(ctx);
      return NULL;
    }
#else
    BN_rshift(m_shifted, m_full, rho + alpha);
#endif

// Mask the bits to the size of m_max
#ifdef ENABLE_MEMORY_CHECKS
    if (!BN_mask_bits(m_shifted, m_max)) {
      log_message(LOG_FATAL, "BN_mask_bits failed for index %zu\n", i);
      BN_free(decrypted_list[i]);
      // Free already allocated BIGNUMs
      for (size_t j = 0; j < i; j++) {
        BN_free(decrypted_list[j]);
      }
      free(decrypted_list);
      BN_free(m_full);
      BN_free(m_shifted);
      BN_CTX_free(ctx);
      return NULL;
    }
#else
    BN_mask_bits(m_shifted, m_max);
#endif

// Copy the masked value to the decrypted message
#ifdef ENABLE_MEMORY_CHECKS
    if (!BN_copy(decrypted_list[i], m_shifted)) {
      log_message(LOG_FATAL, "BN_copy failed for index %zu\n", i);
      BN_free(decrypted_list[i]);
      // Free already allocated BIGNUMs
      for (size_t j = 0; j < i; j++) {
        BN_free(decrypted_list[j]);
      }
      free(decrypted_list);
      BN_free(m_full);
      BN_free(m_shifted);
      BN_CTX_free(ctx);
      return NULL;
    }
#else
    BN_copy(decrypted_list[i], m_shifted);
#endif
  }

  // Free temporary BIGNUMs and context
  BN_free(m_full);
  BN_free(m_shifted);
  BN_CTX_free(ctx);

  return decrypted_list;
}