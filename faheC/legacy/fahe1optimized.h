#ifndef FAHE1OPTIMIZED_H
#define FAHE1OPTIMIZED_H

#include "fahe1.h"

fahe1 *fahe1_init_op(const fahe_params *params);

void fahe1_free_op(fahe1 *fahe1_instance);

fahe1_key fahe1_keygen_op(int lambda, int m_max, int alpha);

BIGNUM *fahe1_encrypt_op(BIGNUM *p, BIGNUM *X, int rho, int alpha, BIGNUM *message);

BIGNUM **fahe1_encrypt_list_op(BIGNUM *p, BIGNUM *X, int rho, int alpha,
                           BIGNUM **message_list, BIGNUM *list_size);

BIGNUM *fahe2_decrypt_op(BIGNUM *p, int m_max, int rho, int alpha,
                     BIGNUM *ciphertext);

BIGNUM **fahe1_decrypt_list_op(BIGNUM *p, int m_max, int rho, int alpha,
                           BIGNUM **ciphertext_list, BIGNUM *list_size);
#endif  // FAHE1OPTIMIZED_H