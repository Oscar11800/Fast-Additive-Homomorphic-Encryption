/**
 * @file fahe2optimized.h
 * @brief Header file for fahe2.c, the main file for Fast Additive Homomorphic
 * Encryption 2 operations such as encryption, decryption, and key generation.
 *
 * This file contains the following structs: fahe_params, fahe1_key, fahe1
 *                and the following methods: fahe1_init, fahe1_free
 * fahe1_keygen, fahe1_encrypt, fahe1_encrypt_list, fahe1_decrypt
 *
 * @author Oscar Chen
 * @date 2024-07-23
 */

#ifndef FAHE2OPTIMIZED_H
#define FAHE2OPTIMIZED_H

#include <openssl/bn.h>

#include "fahe2.h"  //for the fahe_params struct
/**
 * @todo Allow for dynamic num_additions and have 2**(alpha-1) be the default
 *
 * @brief Initializes the fahe2 struct.
 *
 * This function takes in an fahe_params struct. It first safely
 * allocates memory for the fahe1 struct. Then it calls fahe2_keygen
 * to initialize the fahe1_key struct with the params inputs.
 * It then initializes (BIGNUM) num_additions and sets it to 2**(alpha-1).
 *
 * @note Use this function once to initialize the fahe2 struct before using
 *       fahe_encrypt and decrypt methods.
 * @note This method calls fahe1_keygen, so use this instead of keygen.
 *
 * @param[in] params A fahe_params struct containing the following fields:
 *                   - lambda: @see fahe2_key struct
 *                   - m_max: @see fahe2_key struct
 *                   - alpha: @see fahe2_key struct
 *                   - msg_size: @see fahe2 struct
 * @return The initialized fahe2 struct
 */
fahe2 *fahe2_init_op(const fahe_params *params);

/**
 * @brief Frees the fahe2 struct.
 *
 * This function frees the fahe2_key pointers (BIGNUMS X and p) first
 * before freeing the fahe2_key struct and the fahe2 struct itself.
 * @param[in] params An instance of the fahe1 struct (@see fahe1 struct):
 *                   - key (fahe2_key): @see fahe2_key struct
 *                   - m_max (int): @see fahe2_key struct
 *                   - alpha (int): @see fahe2_key struct
 *                   - msg_size (BIGNUM): @see fahe2 struct
 */
void fahe2_free_op(fahe2 *fahe2_instance);

/**
 * @brief Creates fahe2_key for an instance of fahe2.
 *
 * This function creates an instance of the fahe2_key struct; @see fahe2_key.
 * After initializing the fahe2_key, it sets its attributes and computes the
 * following variables:
 *                   - rho (int): rho = lambda.
 *                   - eta (double): eta = rho + (2 * alpha) + m_max;
 *                   - gamma (int): gamma =
 *                    (int)(rho / log2(rho) * ((eta - rho) * (eta - rho)));
 *                   - p (BIGINT): p =
 *                    BN_generate_prime_ex(key.p, (int)eta, 1, NULL, NULL,NULL)
 *
 * @param[in] params An instance of the fahe2 struct @see fahe2 struct:
 */
fahe2_key fahe2_keygen_op(int lambda, int m_max, int alpha);

/**
 * @brief Encrypts a plaintext message into ciphertext.
 *
 *
 * This function computes the formula for FAHE2 encryption of a plaintext
 * message. All variables are BIGNUMs and computed using the OPENSSL library.
 * The reason for using BIGNUM instead of strings or long long are because
 * BIGNUMs provide an appropriately large
 * The calculated variables are as follows:
 *                   - q (BIGNUM): A prime number of eta bits in range [0,X].
 *                   - noise (BIGNUM): A random number in range [0,1^rho] bits.
 *                   - M (BIGNUM): The adjusted message value for encryption.
 *                     M = (message << (rho + alpha)) + noise
 *                   - n (BIGNUM): An intermediate product of the prime number
 *                     p and a random number q. n = p * q.
 *                   - c (BIGNUM): The resulting ciphertext.
 *                     @warning ciphertext and become hundreds of thousands of
 *                     bits long. c = n + M.
 *                   - ctx (BIGNUM): Context to manage temporary variables and
 *                     state during BIGNUM operations
 *
 * @param[in] params - key (fahe2_key): @see fahe2_key struct
 *                   - message(BIGNUM): A plaintext message to encrypt into
 *                     ciphertext. Must be <= m_max.
 *
 * @return The encrypted ciphertext. c = n + M. @see variables above.
 */
BIGNUM *fahe2_encrypt_op(fahe2_key key, BIGNUM *message, BN_CTX *ctx);

void *fahe2_thread_encrypt(void *arg);
/**
 * @brief Encrypts a list of plaintext messages into a list of ciphertext.
 *
 * This function, similar to @see fahe1_encrypt, encrypts a list of messages
 * using the same formula and returns a list of ciphertext. The calculated
 * values are the same as for fahe1_encrypt, except it is done for every
 * message which are calculated on a for-loop based on the size of the list.
 *
 * @note: X + 1 is computed only once and reused throughout the list
 * encryption. However, q, noise, M, n, and c are uniquely calculated for each
 * message. This is to maintain security for each message.
 *
 * @param[in] params - p (BIGNUM): @see fahe1_key struct
 *                   - X (BIGNUM): @see fahe1_key struct
 *                   - rho (int): @see fahe1 struct
 *                   - alpha (int): @see fahe1_key struct
 *                   - message_list (BIGNUM*): A list of messages to encrypt.
 *                   - list_size (BIGNUM): The size of message_list.
 *
 * @return The encrypted ciphertext. c = n + M. @see variables above.
 */
BIGNUM **fahe2_encrypt_list_op(fahe2_key key, BIGNUM **message_list,
                               int list_size);

/**
 * @brief Decrypts a ciphertext into plaintext message.
 *
 * This function decrypts ciphertext into its original message, pre-encryption.
 * To do this, the function performs a series of calculations as follows:
 *                   - m_full: m_full = ciphertext % p. This extracts the
 *                     significant part of the original message w/o buffers.
 *                   - m_shifted = m_full >> (rho + alpha): Removes noise.
 *                   - m_masked = m_shifted << m_max. The final decrypted
 *                     message after masking to m_max bits.
 *
 * @param[in] params - p (BIGNUM): @see fahe1_key struct
 *                   - m_max (int): @see fahe1_key struct
 *                   - rho (int): @see fahe1 struct
 *                   - alpha (int): @see fahe1_key struct
 *                   - ciphertext (BIGNUM): The ciphertext to decrypt.
 *
 * @return The decrypted message masked to m_max bits.
 */
BIGNUM *fahe2_decrypt_op(fahe2_key key, BIGNUM *ciphertext, BN_CTX *ctx);
/**
 * @brief Decrypts a list of ciphertext into a list of plaintext messages.
 *
 * This function, similar to @see fahe1_decrypt, decrypts a list of ciphertext
 * using the same formula and returns a list of the original messages,
 * respecting ordering. The calculated values are the same as for
 * fahe1_decryppt, except it is done for every ciphertext which are calculated
 * on a for-loop based on the size of the list.
 *
 * @note: X + 1 is computed only once and reused throughout the list
 * encryption. However, q, noise, M, n, and c are uniquely calculated for each
 * message. This is to maintain security for each message.
 *
 * @param[in] params - p (BIGNUM): @see fahe1_key struct
 *                   - m_max (int): @see fahe1_key struct
 *                   - rho (int): @see fahe1 struct
 *                   - alpha (int): @see fahe1_key struct
 *                   - ciphertext_list (BIGNUM*): The ciphertext to decrypt.
 *                   - list_size (BIGNUM): The size of ciphertext_list.
 *
 * @return A list of decrypted, masked messages
 */
BIGNUM **fahe2_decrypt_list_op(fahe2_key key, BIGNUM **ciphertext_list,
                               BIGNUM *list_size, BN_CTX *ctx);

#endif  // FAHE2optimized
