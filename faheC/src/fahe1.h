/**
 * @file fahe1.h
 * @brief Header file for fahe1.c, the main file for Fast Additive Homomorphic
 * Encryption operations such as encryption, decryption, and key generation.
 *
 * This file contains the following structs: fahe_params, fahe1_key, fahe1
 *                and the following methods: fahe1_init, fahe1_free
 * fahe1_keygen, fahe1_encrypt, fahe1_encrypt_list, fahe1_decrypt
 *
 * @author Oscar Chen
 * @date 2024-07-23
 */

#ifndef FAHE1_H
#define FAHE1_H

#include <openssl/bn.h>

/**
 * @brief Structure to hold the parameters to pass into fahe1_init.
 *
 * This structure is used for running tests on instances of fahe1.
 *
 * @example
 * // Example of initializing fahe_params
 * fahe_params params_to_pass_into_fahe_init = {128, 32, 6, 32};
 */
typedef struct {
  int lambda;
  int m_max;
  int alpha;
  int msg_size;
} fahe_params;

/**
 * @typedef fahe1_key
 * @brief Structure representing the full fahe1 key for encryption and
 * decryption.
 */

/**
 * @struct fahe1_key
 *
 * @var fahe1_key: lambda (int)
 * Security parameter; bit length of the key.
 *
 * @var fahe1_key: m_max (int)
 * Max plaintext message size in bits.
 *
 * @var fahe1_key: alpha (int)
 * Determines encryption noise level and the safe max number of additions.\
 *
 * @var fahe1_key: X (BIGNUM*)
 * X = (2**rho)/p. Affects encrypted ciphertext.
 *
 * @var fahe1_key: p (BIGNUM*)
 * Random prime number of size (eta) bits.
 */
typedef struct {
  int lambda;
  int m_max;
  int alpha;
  int rho;
  BIGNUM *X;
  BIGNUM *p;
} fahe1_key;

/**
 * @typedef fahe1
 * @brief Fast Additive Homomorphic Encryption structure.
 *
 * This structure contains all the necessary parameters and keys for performing
 * Fast Additive Homomorphic Encryption (FAHE). Only one instance of this
 * structure is needed for any set of messages of the same size and security
 * parameters. It can be reused for encrypting and decrypting multiple messages
 * with the same characteristics.
 *
 * @note This struct is reusable for all messages of the same size and with the
 *       same desirable security variables.
 */

/**
 * @struct fahe1
 *
 * @var fahe1::key (fahe1_key)
 * Full key structure. Refer to the fahe1_key struct for details.
 *
 * @var fahe1::msg_size (unsigned int)
 * Size of accepted plaintext message, in bits. This is usually used for
 message generation.
 *
 * @var fahe1::num_additions (BIGNUM)
 * Maximum number of additions that can be performed. This is usually set to
 * 2**(alpha-1).
 *
 * @note num_additions is a BIGNUM because with a sufficiently large alpha,
 * num_additions may surpass 32 and even 64 bits.
 */
typedef struct {
  fahe1_key key;
  unsigned int msg_size;
  BIGNUM *num_additions;
} fahe1;

/**
 * @todo Allow for dynamic num_additions and have 2**(alpha-1) be the default
 *
 * @brief Initializes the fahe1 struct.
 *
 * This function takes in an fahe_params struct. It first safely
 * allocates memory for the fahe1 struct. Then it calls fahe1_keygen
 * to initialize the fahe1_key struct with the params inputs.
 * It then initializes (BIGNUM) num_additions and sets it to 2**(alpha-1).
 *
 * @note Use this function once to initialize the fahe1 struct before using
 *       fahe_encrypt and decrypt methods.
 * @note This method calls fahe1_keygen, so use this instead of keygen.
 *
 * @param[in] params A fahe_params struct containing the following fields:
 *                   - lambda: @see fahe1_key struct
 *                   - m_max: @see fahe1_key struct
 *                   - alpha: @see fahe1_key struct
 *                   - msg_size: @see fahe1 struct
 * @return The initialized fahe1 struct
 */
fahe1 *fahe1_init(const fahe_params *params);

/**
 * @brief Frees the fahe1 struct.
 *
 * This function frees the fahe1_key pointers (BIGNUMS X and p) first
 * before freeing the fahe1_key struct and the fahe1 struct itself.
 * @param[in] params An instance of the fahe1 struct (@see fahe1 struct):
 *                   - key (fahe1_key): @see fahe1_key struct
 *                   - m_max (int): @see fahe1_key struct
 *                   - alpha (int): @see fahe1_key struct
 *                   - msg_size (BIGNUM): @see fahe1 struct
 */
void fahe1_free(fahe1 *fahe1_instance);

/**
 * @brief Creates fahe1_key for an instance of fahe1.
 *
 * This function creates an instance of the fahe1_key struct; @see fahe1_key.
 * After initializing the fahe1_key, it sets its attributes and computes the
 * following variables:
 *                   - rho (int): rho = lambda.
 *                   - eta (double): eta = rho + (2 * alpha) + m_max;
 *                   - gamma (int): gamma =
 *                    (int)(rho / log2(rho) * ((eta - rho) * (eta - rho)));
 *                   - p (BIGINT): p =
 *                    BN_generate_prime_ex(key.p, (int)eta, 1, NULL, NULL,NULL)
 *
 *  * @param[in] params An instance of the fahe1 struct (@see fahe1 struct):
 */
fahe1_key fahe1_keygen(int lambda, int m_max, int alpha);

/**
 * @brief Encrypts a plaintext message into ciphertext.
 * 
 * This function computes the formula   
 */
BIGNUM *fahe1_encrypt(BIGNUM *p, BIGNUM *X, int rho, int alpha,
                      BIGNUM *message);

/**
 * @brief Encrypts a list of plaintext messages into a list of ciphertext.
 *
 */
BIGNUM **fahe1_encrypt_list(BIGNUM *p, BIGNUM *X, int rho, int alpha,
                            BIGNUM **message_list, BIGNUM *list_size);

BIGNUM *fahe1_decrypt(BIGNUM *p, int m_max, int rho, int alpha,
                      BIGNUM *ciphertext);
BIGNUM **fahe1_decrypt_list(BIGNUM *p, int m_max, int rho, int alpha,
                            BIGNUM **ciphertext_list, BIGNUM *list_size);
#endif  // FAHE1_H