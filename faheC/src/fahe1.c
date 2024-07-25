/**
 * @file fahe1.c
 * @brief Implementation of Fast Additive Homomorphic Encryption (FAHE1)
 *
 * This file contains the implementation of various functions required
 * for the Fast Additive Homomorphic Encryption (FAHE1) scheme.
 * These include initialization, key generation, encryption, and
 * decryption functions, along with helper functions
 * for managing BIGNUM structures.
 *
 * The main functionalities provided by this file are:
 * - Initialization of the FAHE1 structure
 * - Key generation for FAHE1
 * - Encryption of plaintext message(s)
 * - Decryption of ciphertext(s)
 *
 * @note The functions in this file use OpenSSL's BIGNUM library for
 * handling large integers.
 *
 * @warning This implementation assumes that OpenSSL's BIGNUM library is
 * properly installed and configured. Find more information here: @link
 * https://github.com/openssl/openssl
 *
 * @example
 * // Example of initializing fahe_params and using fahe1 functions.
 * fahe_params params = {128, 32, 6, 32};
 * fahe1 *fahe = fahe1_init(&params);
 * // Use fahe for encryption and decryption...
 * fahe1_free(fahe);
 *
 * Dependencies:
 * - math.h
 * - openssl/bn.h
 * - helper.h
 * - logger.h
 *
 * @see fahe1.h for the documetation of the functions implemented in this file.
 * @see helper.h for additional helper functions such as random primes
 * @see logger.h for conditional logging functionalities.
 * @see fahe1optimized.c for the fastest (not as safe) version of
 * these functions without memory checks nor logging.
 */

#include "fahe1.h"

#include <math.h>
#include <openssl/bn.h>

#include "helper.h"
#include "logger.h"

fahe1 *fahe1_init(const fahe_params *params) {
  log_message(LOG_INFO, "Fahe1 init start...\n");

  // Allocate memory for fahe1 struct
  fahe1 *fahe1_instance = (fahe1 *)malloc(sizeof(fahe1));
  if (!fahe1_instance) {
    log_message(LOG_FATAL, "Memory allocation for fahe2_union struct failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Memory successfully allocated for fahe1_instance\n");

  //  Initialize fahe1 struct attributes: key, msg_size, num_additions
  // Generate fahe1 key
  fahe1_instance->key =
      fahe1_keygen(params->lambda, params->m_max, params->alpha);

  // Assign message size
  fahe1_instance->msg_size = params->msg_size;

  // Initialize num_additions
  fahe1_instance->num_additions = BN_new();
  if (!fahe1_instance->num_additions) {
    log_message(LOG_FATAL, "Memory allocation for BIGNUM failed\n");
    free(fahe1_instance);
    exit(EXIT_FAILURE);
  }
  BN_one(fahe1_instance->num_additions);
  // Set num_additions to 2**(alpha-1)
  BN_lshift(fahe1_instance->num_additions, fahe1_instance->num_additions,
            (fahe1_instance->key.alpha) - 1);

  log_message(LOG_INFO, "Debug: fahe1_instance initialized\n");
  return fahe1_instance;
}

void fahe1_free(fahe1 *fahe1_instance) {
  if (!fahe1_instance) {
    log_message(LOG_ERROR, "No fahe1 to release.");
    return;
  }
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
  // Assign key's int attributes
  fahe1_key key;

  key.lambda = lambda;
  key.m_max = m_max;
  key.alpha = alpha;

  // Calculate and init key's BIGNUM attributes
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

  // Calculating X = (2^gamma) / p...
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

  // Calculate (2^gamma)/p
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

  log_message(LOG_INFO, "FAHE1 Key successfully generated.\n");

  return key;
}

BIGNUM *fahe1_encrypt(BIGNUM *p, BIGNUM *X, int rho, int alpha,
                      BIGNUM *message) {
  log_message(LOG_DEBUG, "Initializing encryption...");
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

  log_message(LOG_DEBUG,
              "Debug: Successfully initialized encryption BIGNUM variables\n");

  // Calculating q < X + 1
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

  log_message(LOG_DEBUG, "Debug: X = %s\n", BN_bn2dec(X));

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

  log_message(LOG_DEBUG, "Debug: X+1 = %s\n", BN_bn2dec(X_plus_one));

  q = rand_bignum_below(X_plus_one);
  if (!q) {
    log_message(LOG_FATAL, "rand_bignum_below failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: q = %s\n", BN_bn2dec(q));
  BN_free(X_plus_one);

  // Generate random noise of bit length rho
  noise = rand_bits_below(rho);
  if (!noise) {
    log_message(LOG_FATAL, "rand_bits_below failed\n");
    exit(EXIT_FAILURE);
  }

  log_message(LOG_DEBUG, "Debug: noise = %s\n", BN_bn2dec(noise));

  // M = (message << (rho + alpha)) + noise
  if (!BN_set_word(rho_alpha, rho + alpha)) {
    log_message(LOG_FATAL, "BN_set_word failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: rho+alpha = %s\n", BN_bn2dec(rho_alpha));

  if (!BN_lshift(rho_alpha_shift, message, rho + alpha)) {
    log_message(LOG_FATAL, "BN_lshift failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: message << (rho + alpha) = %s\n",
              BN_bn2dec(rho_alpha_shift));

  if (!BN_add(M, rho_alpha_shift, noise)) {
    log_message(LOG_FATAL, "BN_add for M failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: M = %s\n", BN_bn2dec(M));

  // n = p * q
  if (!BN_mul(n, p, q, ctx)) {
    log_message(LOG_FATAL, "BN_mul failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: n = %s\n", BN_bn2dec(n));

  // c = n + M
  if (!BN_add(c, n, M)) {
    log_message(LOG_FATAL, "BN_add for c failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: c = %s\n", BN_bn2dec(c));

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

BIGNUM **fahe1_encrypt_list(BIGNUM *p, BIGNUM *X, int rho, int alpha,
                            BIGNUM **message_list, BIGNUM *list_size) {
  log_message(LOG_INFO, "Initializing List Encryption");

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
    log_message(LOG_FATAL, "Memory allocation failed\n");
    return NULL;
  }
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
  log_message(LOG_DEBUG, "Debug: X = %s\n", BN_bn2dec(X));
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
  log_message(LOG_DEBUG, "Debug: X + 1 = %s\n", BN_bn2dec(X_plus_one));

  // loop through each message and perform q, noise, M, n, c calculations
  for (int i = 0; i < BN_get_word(list_size); i++) {
    // q -> [0,X]
    q = rand_bignum_below(X_plus_one);
    if (!q) {
      log_message(LOG_FATAL, "rand_bignum_below failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_DEBUG, "Debug: q = %s\n", BN_bn2dec(q));

    // noise > [0, 1^rho] bits
    noise = rand_bits_below(rho);
    if (!noise) {
      log_message(LOG_FATAL, "rand_bits_below failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_FATAL, "Debug: noise = %s\n", BN_bn2dec(noise));

    // calculating M...
    if (!BN_set_word(rho_alpha, rho + alpha)) {
      log_message(LOG_FATAL, "BN_set_word failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_FATAL, "Debug: rho + alpha = %s\n", BN_bn2dec(rho_alpha));

    // Creating ciphertext...
    ciphertext_list[i] = BN_new();
    if (ciphertext_list[i] == NULL) {
      log_message(LOG_FATAL, "BN_new failed for index %d\n", i);
      for (int j = 0; j < i; j++) {
        BN_free(ciphertext_list[j]);
      }
      free(ciphertext_list);
      exit(EXIT_FAILURE);
    }

    if (!BN_lshift(rho_alpha_shift, message_list[i], rho + alpha)) {
      log_message(LOG_FATAL, "BN_lshift failed\n");
      for (int j = 0; j <= i; j++) {
        BN_free(ciphertext_list[j]);
      }
      free(ciphertext_list);
      exit(EXIT_FAILURE);
    }
    log_message(LOG_FATAL, "Debug: message << (rho + alpha) = %s\n",
                BN_bn2dec(rho_alpha_shift));

    // M = (message << (rho + alpha)) + noise
    if (!BN_add(M, rho_alpha_shift, noise)) {
      log_message(LOG_FATAL, "BN_add for M failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_FATAL, "Debug: M = %s\n", BN_bn2dec(M));

    // n = p * q
    if (!BN_mul(n, p, q, ctx)) {
      log_message(LOG_FATAL, "BN_mul failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_FATAL, "Debug: n = %s\n", BN_bn2dec(n));

    // c = n + M
    if (!BN_add(c, n, M)) {
      log_message(LOG_FATAL, "BN_add for c failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_DEBUG, "Debug: c = %s\n", BN_bn2dec(c));

    if (!BN_copy(ciphertext_list[i], c)) {
      log_message(LOG_FATAL, "BN_copy failed for ciphertext_list[%d]\n", i);
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

BIGNUM *fahe1_decrypt(BIGNUM *p, int m_max, int rho, int alpha,
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
  log_message(LOG_DEBUG, "Debug: m_full = %s\n", BN_bn2dec(m_full));

  // m_shifted = m_full >> (rho + alpha)
  if (!BN_rshift(m_shifted, m_full, rho + alpha)) {
    log_message(LOG_FATAL, "BN_rshift failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: m_shifted before masking = %s\n",
              BN_bn2dec(m_shifted));

  // Mask the bits to the size of m_max
  if (!BN_mask_bits(m_shifted, m_max)) {
    log_message(LOG_FATAL, "BN_mask_bits failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug:  m_shifted after masking = %s\n",
              BN_bn2dec(m_masked));

  // Assign the masked value to m_masked
  if (!BN_copy(m_masked, m_shifted)) {
    log_message(LOG_FATAL, "BN_copy failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: m_masked after copying = %s\n",
              BN_bn2dec(m_masked));

  // Free allocated memory
  BN_free(m_full);
  BN_free(m_shifted);
  BN_CTX_free(ctx);

  return m_masked;
}

BIGNUM **fahe1_decrypt_list(BIGNUM *p, int m_max, int rho, int alpha,
                            BIGNUM **ciphertext_list, BIGNUM *list_size) {
  log_message(LOG_DEBUG, "Decrypting ciphertext list...");

  // Initialize BIGNUM values
  BIGNUM *m_full = BN_new();
  BIGNUM *m_shifted = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!m_full || !m_shifted || !ctx) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  // Allocate memory for the list of decrypted messages
  BIGNUM **decrypted_list = malloc(BN_get_word(list_size) * sizeof(BIGNUM *));
  if (decrypted_list == NULL) {
    log_message(LOG_FATAL, "Memory allocation for decrypted_list failed\n");
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

    // m_full = ciphertext % p
    if (!BN_mod(m_full, ciphertext_list[i], p, ctx)) {
      log_message(LOG_FATAL, "BN_mod failed for index %zu\n", i);
      BN_free(decrypted_list[i]);
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
      log_message(LOG_FATAL, "BN_rshift failed for index %zu\n", i);
      BN_free(decrypted_list[i]);
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
      log_message(LOG_FATAL, "BN_mask_bits failed for index %zu\n", i);
      BN_free(decrypted_list[i]);
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
      log_message(LOG_FATAL, "BN_copy failed for index %zu\n", i);
      BN_free(decrypted_list[i]);
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