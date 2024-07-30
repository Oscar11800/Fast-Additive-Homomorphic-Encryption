/**
 * @file fahe2.c
 * @brief Implementation of Fast Additive Homomorphic Encryption (FAHE2)
 *
 * This file contains the implementation of various functions required
 * for the Fast Additive Homomorphic Encryption (FAHE2) scheme.
 * These include initialization, key generation, encryption, and
 * decryption functions, along with helper functions
 * for managing BIGNUM structures.
 *
 * The main functionalities provided by this file are:
 * - Initialization of the fahe2 structure
 * - Key generation for fahe2
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
 * // Example of initializing fahe_params and using fahe2 functions.
 * fahe_params params = {128, 32, 6, 32};
 * fahe2 *fahe = fahe2_init(&params);
 * // Use fahe for encryption and decryption...
 * fahe2_free(fahe);
 *
 * Dependencies:
 * - math.h
 * - openssl/bn.h
 * - helper.h
 * - logger.h
 *
 * @see fahe2.h for the documetation of the functions implemented in this file.
 * @see helper.h for additional helper functions such as random primes
 * @see logger.h for conditional logging functionalities.
 */
#include "fahe2.h"

#include <math.h>
#include <openssl/bn.h>

#include "helper.h"
#include "logger.h"

fahe2 *fahe2_init(const fahe_params *params) {
  log_message(LOG_INFO, "Fahe2 init start...\n");

  // Allocate memory for fahe2 struct
  fahe2 *fahe2_instance = (fahe2 *)malloc(sizeof(fahe2));
  if (!fahe2_instance) {
    log_message(LOG_FATAL,
                "Memory allocation for fahe2_instance struct failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Memory successfully allocated for fahe2_instance\n");

  //  Initialize fahe2 struct attributes: key, msg_size, num_additions
  // Generate fahe2 key
  fahe2_instance->key =
      fahe2_keygen(params->lambda, params->m_max, params->alpha);

  // Assign message size
  fahe2_instance->msg_size = params->msg_size;

  // Initialize num_additions
  fahe2_instance->num_additions = BN_new();
  if (!fahe2_instance->num_additions) {
    log_message(LOG_FATAL, "Memory allocation for BIGNUM failed\n");
    free(fahe2_instance);
    exit(EXIT_FAILURE);
  }
  BN_one(fahe2_instance->num_additions);
  // Set num_additions to 2**(alpha-1)
  BN_lshift(fahe2_instance->num_additions, fahe2_instance->num_additions,
            (fahe2_instance->key.alpha) - 1);

  log_message(LOG_INFO, "Debug: fahe2_instance initialized\n");
  return fahe2_instance;
}

void fahe2_free(fahe2 *fahe2_instance) {
  if (!fahe2_instance) {
    log_message(LOG_ERROR, "No fahe2 to release.");
    return;
  }
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
  // Assign key's int attributes
  fahe2_key key;

  key.lambda = lambda;
  key.m_max = m_max;
  key.alpha = alpha;
  key.pos = rand_int_below(lambda);
  // Calculate and init key's BIGNUM attributes
  int rho = lambda + alpha + m_max;
  key.rho = rho;
  int eta = rho + alpha;
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

  // Calculate X = (2^gamma)/p
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

  log_message(LOG_INFO, "FAHE2 Key successfully generated.\n");

  return key;
}

BIGNUM *fahe2_encrypt(fahe2_key key, BIGNUM *message, BN_CTX *ctx) {
  log_message(LOG_DEBUG, "Initializing encryption...");

  // Initialize BIGNUM values
  BIGNUM *q = NULL;
  BIGNUM *noise1 = NULL;
  BIGNUM *noise2 = NULL;
  BIGNUM *M = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *pos_alpha_shift = BN_new();
  BIGNUM *pos_max_alpha_shift = BN_new();
  BIGNUM *temp = BN_new();  // Temporary variable for intermediate addition

  if (!M || !n || !c || !pos_alpha_shift || !pos_max_alpha_shift || !temp ||
      !ctx) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  log_message(LOG_DEBUG,
              "Successfully initialized encryption BIGNUM variables\n");

  // Calculating q < X + 1
  BIGNUM *X_plus_one = BN_new();
  if (!X_plus_one) {
    log_message(LOG_FATAL, "BN_new for X_plus_one failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "BN_new for X_plus_one succeeded\n");

  if (!key.X) {
    log_message(LOG_FATAL, "Input BIGNUM X is NULL\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Input BIGNUM X is not NULL\n");

  log_message(LOG_DEBUG, "X = %s\n", BN_bn2dec(key.X));

  if (!BN_copy(X_plus_one, key.X)) {
    log_message(LOG_FATAL, "BN_copy failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "BN_copy succeeded\n");

  if (!BN_add_word(X_plus_one, 1)) {
    log_message(LOG_FATAL, "BN_add_word failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "BN_add_word succeeded\n");

  log_message(LOG_DEBUG, "X+1 = %s\n", BN_bn2dec(X_plus_one));

  q = rand_bignum_below(X_plus_one);
  if (!q) {
    log_message(LOG_FATAL, "rand_bignum_below failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "q = %s\n", BN_bn2dec(q));
  BN_free(X_plus_one);
  log_message(LOG_DEBUG, "POS: %c", key.pos);
  // Generate noise 2
  noise2 = rand_bits_below((int)(key.lambda - key.pos));
  if (!noise2) {
    log_message(LOG_FATAL, "rand_bits_below failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "noise2 = %s\n", BN_bn2dec(noise2));

  // (noise2 << (pos + m_max + alpha))
  if (!BN_lshift(pos_max_alpha_shift, noise2,
                 key.pos + key.m_max + key.alpha)) {
    log_message(LOG_FATAL, "BN_lshift failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "noise2 << (pos + m_max + alpha) = %s\n",
              BN_bn2dec(pos_max_alpha_shift));

  // message << (pos + alpha)
  if (!BN_lshift(pos_alpha_shift, message, key.pos + key.alpha)) {
    log_message(LOG_FATAL, "BN_lshift failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "message << (pos + alpha) = %s\n",
              BN_bn2dec(pos_alpha_shift));

  // M = (noise2 << (pos + m_max + alpha)) + (message << (pos + alpha)) + noise1
  if (!BN_add(temp, pos_max_alpha_shift, pos_alpha_shift)) {
    log_message(LOG_FATAL, "BN_add failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(
      LOG_DEBUG,
      "(noise2 << (pos + m_max + alpha)) + (message << (pos + alpha)) = %s\n",
      BN_bn2dec(temp));

  noise1 = rand_bits_below(key.pos);
  if (!noise1) {
    log_message(LOG_FATAL, "rand_bits_below failed for noise1\n");
    exit(EXIT_FAILURE);
  }

  if (!BN_add(M, temp, noise1)) {
    log_message(LOG_FATAL, "BN_add failed for M\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "M = %s\n", BN_bn2dec(M));
  BN_free(noise1);

  // n = p * q
  if (!BN_mul(n, key.p, q, ctx)) {
    log_message(LOG_FATAL, "BN_mul failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "n = %s\n", BN_bn2dec(n));

  // c = n + M
  if (!BN_add(c, n, M)) {
    log_message(LOG_FATAL, "BN_add failed for c\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "c = %s\n", BN_bn2dec(c));

  // Free temporary BIGNUMs
  BN_free(q);
  BN_free(noise2);
  BN_free(M);
  BN_free(n);
  BN_free(pos_alpha_shift);
  BN_free(pos_max_alpha_shift);
  BN_free(temp);

  return c;
}

BIGNUM **fahe2_encrypt_list(fahe2_key key, BIGNUM **message_list, int list_size, BN_CTX *ctx) {
  log_message(LOG_INFO, "Initializing List Encryption");
  log_message(LOG_DEBUG, "LIST SIZE: %d\n", list_size);

  // Initialize BIGNUM values
  BIGNUM *q = NULL;
  BIGNUM *noise1 = NULL;
  BIGNUM *noise2 = NULL;
  BIGNUM *M = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *pos_alpha_shift = BN_new();
  BIGNUM *pos_max_alpha_shift = BN_new();
  BIGNUM *temp = BN_new();  // Temporary variable for intermediate addition

  if (!M || !n || !c || !pos_alpha_shift || !pos_max_alpha_shift || !temp ||
      !ctx) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  log_message(LOG_DEBUG,
              "Successfully initialized encryption BIGNUM variables\n");

  // Calculating q < X + 1
  BIGNUM *X_plus_one = BN_new();
  if (!X_plus_one) {
    log_message(LOG_FATAL, "BN_new for X_plus_one failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "BN_new for X_plus_one succeeded\n");

  if (!key.X) {
    log_message(LOG_FATAL, "Input BIGNUM X is NULL\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Input BIGNUM X is not NULL\n");

  log_message(LOG_DEBUG, "X = %s\n", BN_bn2dec(key.X));

  if (!BN_copy(X_plus_one, key.X)) {
    log_message(LOG_FATAL, "BN_copy failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "BN_copy succeeded\n");

  if (!BN_add_word(X_plus_one, 1)) {
    log_message(LOG_FATAL, "BN_add_word failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "X+1 = %s\n", BN_bn2dec(X_plus_one));

  BIGNUM **ciphertext_list = malloc(list_size * sizeof(BIGNUM *));
  if (ciphertext_list == NULL) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    return NULL;
  }

  // Loop through each message and perform encryption
  for (int i = 0; i < list_size; i++) {
    q = rand_bignum_below(X_plus_one);
    if (!q) {
      log_message(LOG_FATAL, "rand_bignum_below failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_DEBUG, "q = %s\n", BN_bn2dec(q));

    // Generate noise 2
    noise2 = rand_bits_below(key.lambda - key.pos);
    if (!noise2) {
      log_message(LOG_FATAL, "rand_bits_below failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_DEBUG, "noise2 = %s\n", BN_bn2dec(noise2));

    // (noise2 << (pos + m_max + alpha))
    if (!BN_lshift(pos_max_alpha_shift, noise2,
                   key.pos + key.m_max + key.alpha)) {
      log_message(LOG_FATAL, "BN_lshift failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_DEBUG, "noise2 << (pos + m_max + alpha) = %s\n",
                BN_bn2dec(pos_max_alpha_shift));

    // message << (pos + alpha)
    if (!BN_lshift(pos_alpha_shift, message_list[i], key.pos + key.alpha)) {
      log_message(LOG_FATAL, "BN_lshift failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_DEBUG, "message << (pos + alpha) = %s\n",
                BN_bn2dec(pos_alpha_shift));

    // M = (noise2 << (pos + m_max + alpha)) + (message << (pos + alpha)) +
    // noise1
    if (!BN_add(temp, pos_max_alpha_shift, pos_alpha_shift)) {
      log_message(LOG_FATAL, "BN_add failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(
        LOG_DEBUG,
        "(noise2 << (pos + m_max + alpha)) + (message << (pos + alpha)) = %s\n",
        BN_bn2dec(temp));

    if (!BN_add(M, temp, rand_bits_below(key.pos))) {
      log_message(LOG_FATAL, "BN_add failed for M\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_DEBUG, "M = %s\n", BN_bn2dec(M));
    BN_free(noise1);

    // n = p * q
    if (!BN_mul(n, key.p, q, ctx)) {
      log_message(LOG_FATAL, "BN_mul failed\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_DEBUG, "n = %s\n", BN_bn2dec(n));

    // c = n + M
    if (!BN_add(c, n, M)) {
      log_message(LOG_FATAL, "BN_add failed for c\n");
      exit(EXIT_FAILURE);
    }
    log_message(LOG_DEBUG, "c = %s\n", BN_bn2dec(c));

    ciphertext_list[i] = BN_dup(c);
    if (ciphertext_list[i] == NULL) {
      log_message(LOG_FATAL, "BN_dup failed for ciphertext_list[%d]\n", i);
      // Free already allocated ciphertexts in case of failure
      for (int j = 0; j <= i; j++) {
        BN_free(ciphertext_list[j]);
      }
      free(ciphertext_list);
      exit(EXIT_FAILURE);
    }
  }

  // Free other temporary BIGNUMs and context
  BN_free(q);
  BN_free(noise2);
  BN_free(X_plus_one);
  BN_free(M);
  BN_free(n);
  BN_free(c);
  BN_free(pos_alpha_shift);
  BN_free(pos_max_alpha_shift);
  BN_free(temp);

  return ciphertext_list;
}

BIGNUM *fahe2_decrypt(fahe2_key key, BIGNUM *ciphertext, BN_CTX *ctx) {
  BIGNUM *m_full = BN_new();
  BIGNUM *m_shifted = BN_new();
  BIGNUM *m_masked = BN_new();

  if (!m_full || !m_shifted || !m_masked || !ctx) {
    log_message(LOG_FATAL, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  // m_full = ciphertext % p
  if (!BN_mod(m_full, ciphertext, key.p, ctx)) {
    log_message(LOG_FATAL, "BN_mod failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: m_full = %s\n", BN_bn2dec(m_full));

  // m_shifted = m_full >> (pos + alpha)
  if (!BN_rshift(m_shifted, m_full, key.pos + key.alpha)) {
    log_message(LOG_FATAL, "BN_rshift failed\n");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_DEBUG, "Debug: m_shifted before masking = %s\n",
              BN_bn2dec(m_shifted));

  // Mask the bits to the size of m_max
  if (!BN_mask_bits(m_shifted, key.m_max)) {
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

BIGNUM **fahe2_decrypt_list(fahe2_key key, BIGNUM **ciphertext_list,
                            BIGNUM *list_size, BN_CTX *ctx) {
  log_message(LOG_INFO, "Decrypting ciphertext list...");

  // Initialize BIGNUM values
  BIGNUM *m_full = BN_new();
  BIGNUM *m_shifted = BN_new();

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
    if (!BN_mod(m_full, ciphertext_list[i], key.p, ctx)) {
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

    // m_shifted = m_full >> (pos + alpha)
    if (!BN_rshift(m_shifted, m_full, key.pos + key.alpha)) {
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
    if (!BN_mask_bits(m_shifted, key.m_max)) {
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

  log_message(LOG_INFO, "Ciphertext list sucessfully decrypted");
  return decrypted_list;
}