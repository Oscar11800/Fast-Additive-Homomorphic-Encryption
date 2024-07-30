#include "fahe1optimized.h"

#include <math.h>
#include <openssl/bn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "fahe1.h"
#include "helper.h"
#include "logger.h"

fahe1 *fahe1_init_op(const fahe_params *params) {
  fahe1 *fahe1_instance = (fahe1 *)malloc(sizeof(fahe1));

  // Generate the key
  fahe1_instance->key =
      fahe1_keygen_op(params->lambda, params->m_max, params->alpha);
  fahe1_instance->msg_size = params->msg_size;

  // Initialize num_additions for fahe1
  fahe1_instance->num_additions = BN_new();

  BN_one(fahe1_instance->num_additions);
  BN_lshift(fahe1_instance->num_additions, fahe1_instance->num_additions,
            (fahe1_instance->key.alpha) - 1);

  return fahe1_instance;
}

void fahe1_free_op(fahe1 *fahe1_instance) {
  BN_free(fahe1_instance->key.p);
  BN_free(fahe1_instance->key.X);
  BN_free(fahe1_instance->num_additions);
  free(fahe1_instance);
}

fahe1_key fahe1_keygen_op(int lambda, int m_max, int alpha) {
  fahe1_key key;

  key.lambda = lambda;
  key.m_max = m_max;
  key.alpha = alpha;

  int rho = lambda;
  key.rho = rho;
  double eta = rho + (2 * alpha) + m_max;
  int gamma = (int)(rho / log2(rho) * ((eta - rho) * (eta - rho)));

  // Generate a large prime p
  key.p = BN_new();
  BN_generate_prime_ex(key.p, (int)eta, 1, NULL, NULL, NULL);

  // Calculate X = (2^gamma) / p using BIGNUM
  BIGNUM *X = BN_new();
  BIGNUM *base = BN_new();
  BIGNUM *gamma_bn = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_set_word(base, 2);
  BN_set_word(gamma_bn, gamma);

  // Calculate 2^gamma
  BN_exp(X, base, gamma_bn, ctx);
  // Divide 2^gamma by p
  BN_div(X, NULL, X, key.p, ctx);
  // Set X in the key structure
  key.X = X;

  // Clean up
  BN_free(base);
  BN_free(gamma_bn);
  BN_CTX_free(ctx);

  return key;
}

BIGNUM *fahe1_encrypt_op(BIGNUM *p, BIGNUM *X, int rho, int alpha,
                     BIGNUM *message) {
  // Initialize BIGNUM values
  BIGNUM *q = NULL;
  BIGNUM *noise = NULL;
  BIGNUM *M = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *rho_alpha_shift = BN_new();
  BIGNUM *rho_alpha = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *X_plus_one = BN_new();

  BN_copy(X_plus_one, X);
  BN_add_word(X_plus_one, 1);
  q = rand_bignum_below(X_plus_one);
  BN_free(X_plus_one);

  noise = rand_bits_below(rho);
  BN_set_word(rho_alpha, rho + alpha);
  BN_lshift(rho_alpha_shift, message, rho + alpha);
  BN_add(M, rho_alpha_shift, noise);
  BN_mul(n, p, q, ctx);
  BN_add(c, n, M);

  BN_free(q);
  BN_free(noise);
  BN_free(M);
  BN_free(n);
  BN_free(rho_alpha_shift);
  BN_free(rho_alpha);
  BN_CTX_free(ctx);

  return c;
}
void *fahe1_thread_encrypt(void *arg) {
  Fahe1EncThreadData *data = (Fahe1EncThreadData *)arg;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *rho_alpha_shift = BN_new();
  BIGNUM *rho_alpha = BN_new();
  BIGNUM *M = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *X_plus_one = BN_new();

  BN_copy(X_plus_one, data->X);
  BN_add_word(X_plus_one, 1);

  for (int i = data->start; i < data->end; i++) {
    BIGNUM *q = rand_bignum_below(X_plus_one);
    BIGNUM *noise = rand_bits_below(data->rho);
    BN_set_word(rho_alpha, data->rho + data->alpha);
    data->ciphertext_list[i] = BN_new();

    BN_lshift(rho_alpha_shift, data->message_list[i], data->rho + data->alpha);
    BN_add(M, rho_alpha_shift, noise);
    BN_mul(n, data->p, q, ctx);
    BN_add(c, n, M);
    BN_copy(data->ciphertext_list[i], c);

    BN_free(q);
    BN_free(noise);
  }

  BN_free(X_plus_one);
  BN_free(M);
  BN_free(n);
  BN_free(c);
  BN_free(rho_alpha_shift);
  BN_free(rho_alpha);
  BN_CTX_free(ctx);

  return NULL;
}

BIGNUM **fahe1_encrypt_list_op(BIGNUM *p, BIGNUM *X, int rho, int alpha, BIGNUM **message_list, BIGNUM *list_size) {
    int num_threads = 1;
    pthread_t threads[num_threads];
    Fahe1EncThreadData thread_data[num_threads];

    BIGNUM **ciphertext_list = malloc(BN_get_word(list_size) * sizeof(BIGNUM *));
    int list_size_int = BN_get_word(list_size);
    int chunk_size = list_size_int / num_threads;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].p = p;
        thread_data[i].X = X;
        thread_data[i].rho = rho;
        thread_data[i].alpha = alpha;
        thread_data[i].message_list = message_list;
        thread_data[i].ciphertext_list = ciphertext_list;
        thread_data[i].start = i * chunk_size;
        thread_data[i].end = (i == num_threads - 1) ? list_size_int : (i + 1) * chunk_size;

        pthread_create(&threads[i], NULL, fahe1_thread_encrypt, &thread_data[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return ciphertext_list;
}

BIGNUM *fahe1_decrypt_op(BIGNUM *p, int m_max, int rho, int alpha,
                     BIGNUM *ciphertext) {
  BIGNUM *m_full = BN_new();
  BIGNUM *m_shifted = BN_new();
  BIGNUM *m_masked = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_mod(m_full, ciphertext, p, ctx);
  BN_rshift(m_shifted, m_full, rho + alpha);
  BN_mask_bits(m_shifted, m_max);

  BN_copy(m_masked, m_shifted);

  BN_free(m_full);
  BN_free(m_shifted);
  BN_CTX_free(ctx);

  return m_masked;
}

void *fahe1_thread_dec(void *arg) {
    Fahe1DecThreadData *data = (Fahe1DecThreadData *)arg;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m_full = BN_new();
    BIGNUM *m_shifted = BN_new();

    for (int i = data->start; i < data->end; i++) {
        data->decrypted_list[i] = BN_new();

        BN_mod(m_full, data->ciphertext_list[i], data->p, ctx);
        BN_rshift(m_shifted, m_full, data->rho + data->alpha);
        BN_mask_bits(m_shifted, data->m_max);
        BN_copy(data->decrypted_list[i], m_shifted);
    }

    BN_free(m_full);
    BN_free(m_shifted);
    BN_CTX_free(ctx);

    return NULL;
}

BIGNUM **fahe1_decrypt_list_op(BIGNUM *p, int m_max, int rho, int alpha, BIGNUM **ciphertext_list, BIGNUM *list_size) {
    int num_threads = 1;
    pthread_t threads[num_threads];
    Fahe1DecThreadData thread_data[num_threads];

    BIGNUM **decrypted_list = malloc(BN_get_word(list_size) * sizeof(BIGNUM *));
    int list_size_int = BN_get_word(list_size);
    int chunk_size = list_size_int / num_threads;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].p = p;
        thread_data[i].m_max = m_max;
        thread_data[i].rho = rho;
        thread_data[i].alpha = alpha;
        thread_data[i].ciphertext_list = ciphertext_list;
        thread_data[i].decrypted_list = decrypted_list;
        thread_data[i].start = i * chunk_size;
        thread_data[i].end = (i == num_threads - 1) ? list_size_int : (i + 1) * chunk_size;

        pthread_create(&threads[i], NULL, fahe1_thread_dec, &thread_data[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return decrypted_list;
}