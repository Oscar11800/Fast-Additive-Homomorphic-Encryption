
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
 * @see fahe2optimized.c for the fastest (not as safe) version of
 * these functions without memory checks nor logging.
 */
#include "fahe2optimized.h"

#include <math.h>
#include <openssl/bn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "helper.h"
#include "logger.h"
#include "threads.h"

fahe2 *fahe2_init_op(const fahe_params *params) {
  // Allocate memory for fahe2 struct
  fahe2 *fahe2_instance = (fahe2 *)malloc(sizeof(fahe2));
  //  Initialize fahe2 struct attributes: key, msg_size, num_additions
  // Generate fahe2 key
  fahe2_instance->key =
      fahe2_keygen(params->lambda, params->m_max, params->alpha);
  // Assign message size
  fahe2_instance->msg_size = params->msg_size;

  // Initialize num_additions
  fahe2_instance->num_additions = BN_new();
  BN_one(fahe2_instance->num_additions);
  // Set num_additions to 2**(alpha-1)
  BN_lshift(fahe2_instance->num_additions, fahe2_instance->num_additions,
            (fahe2_instance->key.alpha) - 1);

  return fahe2_instance;
}

void fahe2_free_op(fahe2 *fahe2_instance) {
  BN_free(fahe2_instance->key.p);
  BN_free(fahe2_instance->key.X);
  BN_free(fahe2_instance->num_additions);
  free(fahe2_instance);
}

fahe2_key fahe2_keygen_op(int lambda, int m_max, int alpha) {
  fahe2_key key;
  key.lambda = lambda;
  key.m_max = m_max;
  key.alpha = alpha;
  key.pos = rand_int_below(lambda);

  int rho = lambda + alpha + m_max;
  key.rho = rho;
  int eta = rho + alpha;
  int gamma = (int)(rho / log2(rho) * ((eta - rho) * (eta - rho)));

  key.p = BN_new();
  BN_generate_prime_ex(key.p, (int)eta, 1, NULL, NULL, NULL);

  BIGNUM *X = BN_new();
  BIGNUM *base = BN_new();
  BIGNUM *gamma_bn = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_set_word(base, 2);
  BN_set_word(gamma_bn, gamma);

  BN_exp(X, base, gamma_bn, ctx);
  BN_div(X, NULL, X, key.p, ctx);

  key.X = X;

  BN_free(base);
  BN_free(gamma_bn);
  BN_CTX_free(ctx);

  return key;
}

BIGNUM *fahe2_encrypt_op(fahe2_key key, BIGNUM *message, BN_CTX *ctx) {
  BIGNUM *q = NULL;
  BIGNUM *noise1 = NULL;
  BIGNUM *noise2 = NULL;
  BIGNUM *M = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *pos_alpha_shift = BN_new();
  BIGNUM *pos_max_alpha_shift = BN_new();
  BIGNUM *temp = BN_new();

  BIGNUM *X_plus_one = BN_new();
  BN_copy(X_plus_one, key.X);
  BN_add_word(X_plus_one, 1);
  q = rand_bignum_below(X_plus_one);
  BN_free(X_plus_one);

  noise2 = rand_bits_below((int)(key.lambda - key.pos));
  BN_lshift(pos_max_alpha_shift, noise2, key.pos + key.m_max + key.alpha);
  BN_lshift(pos_alpha_shift, message, key.pos + key.alpha);

  BN_add(temp, pos_max_alpha_shift, pos_alpha_shift);
  noise1 = rand_bits_below(key.pos);
  BN_add(M, temp, noise1);

  BN_mul(n, key.p, q, ctx);
  BN_add(c, n, M);

  BN_free(q);
  BN_free(noise2);
  BN_free(M);
  BN_free(n);
  BN_free(pos_alpha_shift);
  BN_free(pos_max_alpha_shift);
  BN_free(temp);

  return c;
}

void *fahe2_thread_encrypt(void *arg) {
    Fahe2EncThreadData *data = (Fahe2EncThreadData *)arg;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *q = NULL;
    BIGNUM *noise2 = NULL;
    BIGNUM *M = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *pos_alpha_shift = BN_new();
    BIGNUM *pos_max_alpha_shift = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *X_plus_one = BN_new();

    BN_copy(X_plus_one, data->key.X);
    BN_add_word(X_plus_one, 1);

    for (int i = data->start; i < data->end; i++) {
        q = rand_bignum_below(X_plus_one);
        noise2 = rand_bits_below(data->key.lambda - data->key.pos);
        BN_lshift(pos_max_alpha_shift, noise2, data->key.pos + data->key.m_max + data->key.alpha);
        BN_lshift(pos_alpha_shift, data->message_list[i], data->key.pos + data->key.alpha);
        BN_add(temp, pos_max_alpha_shift, pos_alpha_shift);
        BN_add(M, temp, rand_bits_below(data->key.pos));
        BN_mul(n, data->key.p, q, ctx);
        BN_add(c, n, M);
        data->ciphertext_list[i] = BN_dup(c);

        BN_free(q);
        BN_free(noise2);
    }

    BN_free(X_plus_one);
    BN_free(M);
    BN_free(n);
    BN_free(c);
    BN_free(pos_alpha_shift);
    BN_free(pos_max_alpha_shift);
    BN_free(temp);
    BN_CTX_free(ctx);

    return NULL;
}

BIGNUM **fahe2_encrypt_list_op(fahe2_key key, BIGNUM **message_list, int list_size) {
    int num_threads = 1;  // Number of threads
    pthread_t threads[num_threads];
    Fahe2EncThreadData thread_data[num_threads];

    BIGNUM **ciphertext_list = malloc(list_size * sizeof(BIGNUM *));
    int chunk_size = list_size / num_threads;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].key = key;
        thread_data[i].message_list = message_list;
        thread_data[i].ciphertext_list = ciphertext_list;
        thread_data[i].start = i * chunk_size;
        thread_data[i].end = (i == num_threads - 1) ? list_size : (i + 1) * chunk_size;

        pthread_create(&threads[i], NULL, fahe2_thread_encrypt, &thread_data[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return ciphertext_list;
}

BIGNUM *fahe2_decrypt_op(fahe2_key key, BIGNUM *ciphertext, BN_CTX *ctx) {
  BIGNUM *m_full = BN_new();
  BIGNUM *m_shifted = BN_new();
  BIGNUM *m_masked = BN_new();

  BN_mod(m_full, ciphertext, key.p, ctx);
  BN_rshift(m_shifted, m_full, key.pos + key.alpha);
  BN_mask_bits(m_shifted, key.m_max);
  BN_copy(m_masked, m_shifted);

  BN_free(m_full);
  BN_free(m_shifted);
  return m_masked;
}

BIGNUM **fahe2_decrypt_list_op(fahe2_key key, BIGNUM **ciphertext_list,
                               BIGNUM *list_size, BN_CTX *ctx) {
  BIGNUM *m_full = BN_new();
  BIGNUM *m_shifted = BN_new();

  BIGNUM **decrypted_list = malloc(BN_get_word(list_size) * sizeof(BIGNUM *));
  for (size_t i = 0; i < BN_get_word(list_size); i++) {
    decrypted_list[i] = BN_new();
    BN_mod(m_full, ciphertext_list[i], key.p, ctx);
    BN_rshift(m_shifted, m_full, key.pos + key.alpha);
    BN_mask_bits(m_shifted, key.m_max);
    BN_copy(decrypted_list[i], m_shifted);
  }

  BN_free(m_full);
  BN_free(m_shifted);
  return decrypted_list;
}