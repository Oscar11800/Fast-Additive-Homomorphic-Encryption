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
  if (ciphertext_list == NULL) {
    // fprintf(stderr, "Memory allocation failed\n");
    return NULL;
  }

  if (!M || !n || !c || !rho_alpha_shift || !rho_alpha || !ctx) {
    // fprintf(stderr, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  // fprintf(stderr, "Debug: Initialized BIGNUM variables\n");

  // q < X + 1
  BIGNUM *X_plus_one = BN_new();
  if (!X_plus_one) {
    // fprintf(stderr, "BN_new for X_plus_one failed\n");
    exit(EXIT_FAILURE);
  }
  // fprintf(stderr, "Debug: BN_new for X_plus_one succeeded\n");

  if (!X) {
    // fprintf(stderr, "Input BIGNUM X is NULL\n");
    exit(EXIT_FAILURE);
  }
  // fprintf(stderr, "Debug: Input BIGNUM X is not NULL\n");

  //   //fprintf(stderr, "Debug: X = ");
  //   //BN_print_fp(stderr, X);
  //   //fprintf(stderr, "\n");

  if (!BN_copy(X_plus_one, X)) {
    // fprintf(stderr, "BN_copy failed\n");
    exit(EXIT_FAILURE);
  }
  // fprintf(stderr, "Debug: BN_copy succeeded\n");

  if (!BN_add_word(X_plus_one, 1)) {
    // fprintf(stderr, "BN_add_word failed\n");
    exit(EXIT_FAILURE);
  }
  // fprintf(stderr, "Debug: BN_add_word succeeded\n");

  //   //fprintf(stderr, "Debug: X + 1 = ");
  //   //BN_print_fp(stderr, X_plus_one);
  //   //fprintf(stderr, "\n");

  for (int i = 0; i < BN_get_word(list_size); i++) {
    q = rand_num_below(X_plus_one);
    if (!q) {
      // fprintf(stderr, "rand_num_below failed\n");
      exit(EXIT_FAILURE);
    }
    // //fprintf(stderr, "Debug: q = ");
    // //BN_print_fp(stderr, q);
    // //fprintf(stderr, "\n");

    noise = rand_bits_below(rho);
    if (!noise) {
      // fprintf(stderr, "rand_bits_below failed\n");
      exit(EXIT_FAILURE);
    }
    // fprintf(stderr, "Debug: noise = ");
    // BN_print_fp(stderr, noise);
    // fprintf(stderr, "\n");

    if (!BN_set_word(rho_alpha, rho + alpha)) {
      // fprintf(stderr, "BN_set_word failed\n");
      exit(EXIT_FAILURE);
    }
    // fprintf(stderr, "Debug: rho + alpha = ");
    // BN_print_fp(stderr, rho_alpha);
    // fprintf(stderr, "\n");

    ciphertext_list[i] = BN_new();
    if (ciphertext_list[i] == NULL) {
      // fprintf(stderr, "BN_new failed for index %d\n", i);
      for (int j = 0; j < i; j++) {
        BN_free(ciphertext_list[j]);
      }
      free(ciphertext_list);
      exit(EXIT_FAILURE);
    }

    if (!BN_lshift(rho_alpha_shift, message_list[i], rho + alpha)) {
      // fprintf(stderr, "BN_lshift failed\n");
      for (int j = 0; j <= i; j++) {
        BN_free(ciphertext_list[j]);
      }
      free(ciphertext_list);
      exit(EXIT_FAILURE);
    }
    // fprintf(stderr, "Debug: message << (rho + alpha) = ");
    // BN_print_fp(stderr, rho_alpha_shift);
    // fprintf(stderr, "\n");

    if (!BN_add(M, rho_alpha_shift, noise)) {
      // fprintf(stderr, "BN_add for M failed\n");
      exit(EXIT_FAILURE);
    }
    // //fprintf(stderr, "Debug: M = ");
    // //BN_print_fp(stderr, M);
    // //fprintf(stderr, "\n");

    if (!BN_mul(n, p, q, ctx)) {
      // fprintf(stderr, "BN_mul failed\n");
      exit(EXIT_FAILURE);
    }
    // //fprintf(stderr, "Debug: n = ");
    // //BN_print_fp(stderr, n);
    // //fprintf(stderr, "\n");

    if (!BN_add(c, n, M)) {
      // fprintf(stderr, "BN_add for c failed\n");
      exit(EXIT_FAILURE);
    }
    // //fprintf(stderr, "Debug: c = ");
    // //BN_print_fp(stderr, c);
    // //fprintf(stderr, "\n");

    if (!BN_copy(ciphertext_list[i], c)) {
      // fprintf(stderr, "BN_copy failed for ciphertext_list[%d]\n", i);
      exit(EXIT_FAILURE);
    }

    BN_free(q);
    BN_free(noise);
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

  if (!m_full || !m_shifted || !m_masked || !ctx) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  // m_full = ciphertext % p
  if (!BN_mod(m_full, ciphertext, p, ctx)) {
    log_message(LOG_FATAL, "BN_mod failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: m_full = %c\n", BN_bn2dec(m_full));

  // m_shifted = m_full >> (rho + alpha)
  if (!BN_rshift(m_shifted, m_full, rho + alpha)) {
    log_message(LOG_FATAL, "BN_rshift failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug:  m_shifted before masking = %c\n",
              BN_bn2dec(m_shifted));

  // Mask the bits to the size of m_max
  if (!BN_mask_bits(m_shifted, m_max)) {
    log_message(LOG_FATAL, "BN_mask_bits failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug:  m_shifted after masking = %c\n",
              BN_bn2dec(m_masked));

  // Assign the masked value to m_masked
  if (!BN_copy(m_masked, m_shifted)) {
    log_message(LOG_FATAL, "BN_copy failed\n");
    exit(EXIT_FAILURE);
  }
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

  if (!m_full || !m_shifted || !ctx) {
    // fprintf(stderr, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  // Allocate memory for the list of decrypted messages
  BIGNUM **decrypted_list = malloc(BN_get_word(list_size) * sizeof(BIGNUM *));
  if (decrypted_list == NULL) {
    // fprintf(stderr, "Memory allocation for decrypted_list failed\n");
    BN_free(m_full);
    BN_free(m_shifted);
    BN_CTX_free(ctx);
    return NULL;
  }

  // Decrypt each ciphertext
  for (size_t i = 0; i < BN_get_word(list_size); i++) {
    // Allocate memory for each decrypted message
    decrypted_list[i] = BN_new();
    if (!decrypted_list[i]) {
      // fprintf(stderr, "BN_new failed for index %zu\n", i);
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

    // m_full = ciphertext % p
    if (!BN_mod(m_full, ciphertext_list[i], p, ctx)) {
      // fprintf(stderr, "BN_mod failed for index %zu\n", i);
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

    // m_shifted = m_full >> (rho + alpha)
    if (!BN_rshift(m_shifted, m_full, rho + alpha)) {
      // fprintf(stderr, "BN_rshift failed for index %zu\n", i);
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

    // Mask the bits to the size of m_max
    if (!BN_mask_bits(m_shifted, m_max)) {
      // fprintf(stderr, "BN_mask_bits failed for index %zu\n", i);
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

    // Copy the masked value to the decrypted message
    if (!BN_copy(decrypted_list[i], m_shifted)) {
      // fprintf(stderr, "BN_copy failed for index %zu\n", i);
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
  }

  // Free temporary BIGNUMs and context
  BN_free(m_full);
  BN_free(m_shifted);
  BN_CTX_free(ctx);

  return decrypted_list;
}