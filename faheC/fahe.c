#include "fahe.h"

#include <gmp.h>
#include <math.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

fahe_union *fahe_init(const fahe_params *params, fahe_type type) {
  fahe_union *fahe = (fahe_union *)malloc(sizeof(fahe_union));
  if (!fahe) {
    fprintf(stderr, "Memory allocation for fahe_union struct failed\n");
    exit(EXIT_FAILURE);
  }

  if (type == FAHE1_TYPE) {
    fahe1 *fahe1_instance = &fahe->fahe1_instance;

    // Initialize common params
    fahe1_instance->base.lambda_param = params->lambda_param;
    fahe1_instance->base.m_max = params->m_max;
    fahe1_instance->base.alpha = params->alpha;
    fahe1_instance->base.msg_size = params->msg_size;

    // Initialize num_additions for fahe1
    fahe1_instance->num_additions = BN_new();
    if (!fahe1_instance->num_additions) {
      fprintf(stderr, "Memory allocation for BIGNUM failed\n");
      free(fahe);
      exit(EXIT_FAILURE);
    }
    BN_one(fahe1_instance->num_additions);
    BN_lshift(fahe1_instance->num_additions, fahe1_instance->num_additions,
              (fahe1_instance->base.alpha) - 1);

    // Initialize keys
    // key = (p, m_max, X, rho, alpha)
    fahe1_instance->base.key =
        fahe1_keygen(fahe1_instance->base.lambda_param,
                     fahe1_instance->base.m_max, fahe1_instance->base.alpha);
    if (!fahe1_instance->base.key) {
      fprintf(stderr, "Memory allocation for key failed\n");
      BN_free(fahe1_instance->num_additions);
      free(fahe);
      exit(EXIT_FAILURE);
    }

    // Allocate memory and set enc_key
    fahe1_instance->base.enc_key = (int *)malloc(4 * sizeof(int));
    if (!fahe1_instance->base.enc_key) {
      fprintf(stderr, "Memory allocation for enc_key failed\n");
      BN_free(fahe1_instance->num_additions);
      free(fahe1_instance->base.key);
      free(fahe);
      exit(EXIT_FAILURE);
    }
    fahe1_instance->base.enc_key[0] = fahe1_instance->base.key[0];
    fahe1_instance->base.enc_key[1] = fahe1_instance->base.key[2];
    fahe1_instance->base.enc_key[2] = fahe1_instance->base.key[3];
    fahe1_instance->base.enc_key[3] = fahe1_instance->base.key[4];

    // Allocate memory and set dec_key
    fahe1_instance->base.dec_key = (int *)malloc(4 * sizeof(int));
    if (!fahe1_instance->base.dec_key) {
      fprintf(stderr, "Memory allocation for dec_key failed\n");
      BN_free(fahe1_instance->num_additions);
      free(fahe1_instance->base.key);
      free(fahe1_instance->base.enc_key);
      free(fahe);
      exit(EXIT_FAILURE);
    }
    fahe1_instance->base.dec_key[0] = fahe1_instance->base.key[0];
    fahe1_instance->base.dec_key[1] = fahe1_instance->base.key[1];
    fahe1_instance->base.dec_key[2] = fahe1_instance->base.key[3];
    fahe1_instance->base.dec_key[3] = fahe1_instance->base.key[4];

  } else if (type == FAHE2_TYPE) {
    fahe2 *fahe2_instance = &fahe->fahe2_instance;

    // Initialize common params
    fahe2_instance->base.lambda_param = params->lambda_param;
    fahe2_instance->base.m_max = params->m_max;
    fahe2_instance->base.alpha = params->alpha;
    fahe2_instance->base.msg_size = params->msg_size;

    // Initialize num_additions for fahe2
    fahe2_instance->num_additions = BN_new();
    if (!fahe2_instance->num_additions) {
      fprintf(stderr, "Memory allocation for BIGNUM failed\n");
      free(fahe);
      exit(EXIT_FAILURE);
    }
    BN_one(fahe2_instance->num_additions);
    BN_lshift(fahe2_instance->num_additions, fahe2_instance->num_additions,
              (fahe2_instance->base.alpha) - 1);
  } else {
    fprintf(stderr, "Unknown type for fahe_init\n");
    free(fahe);
    exit(EXIT_FAILURE);
  }
  return fahe;
}

void fahe_free(fahe_union *fahe, fahe_type type) {
  if (!fahe) {
    return;
  }

  if (type == FAHE1_TYPE) {
    fahe1 *fahe1_instance = &fahe->fahe1_instance;

    // Free num_additions BIGNUM
    if (fahe1_instance->num_additions) {
      BN_free(fahe1_instance->num_additions);
    }

    // Free the key arrays
    if (fahe1_instance->base.key) {
      free(fahe1_instance->base.key);
    }
    if (fahe1_instance->base.enc_key) {
      free(fahe1_instance->base.enc_key);
    }
    if (fahe1_instance->base.dec_key) {
      free(fahe1_instance->base.dec_key);
    }
  } else if (type == FAHE2_TYPE) {
    fahe2 *fahe2_instance = &fahe->fahe2_instance;

    // Free num_additions BIGNUM
    if (fahe2_instance->num_additions) {
      BN_free(fahe2_instance->num_additions);
    }

    // Free the key arrays
    if (fahe2_instance->base.key) {
      free(fahe2_instance->base.key);
    }
    if (fahe2_instance->base.enc_key) {
      free(fahe2_instance->base.enc_key);
    }
    if (fahe2_instance->base.dec_key) {
      free(fahe2_instance->base.dec_key);
    }
  } else {
    fprintf(stderr, "Unknown type for fahe_free\n");
    return;
  }
  // Free the union itself
  free(fahe);
}

int *fahe1_keygen(int lambda_param, int m_max, int alpha) {
  int rho = lambda_param;
  double eta = rho + (2 * alpha) + m_max;
  int gamma = (int)(rho / log2(rho) * ((eta - rho) * (eta - rho)));
  // Generate a large prime p
  BIGNUM *p = BN_new();
  if (!p) {
    fprintf(stderr, "BN_new failed\n");
  }
  if (!BN_generate_prime_ex(p, (int)eta, 1, NULL, NULL, NULL)) {
    fprintf(stderr, "BN_generate_prime_ex failed\n");
  }
  // Convert BIGNUM p to an int
  int p_int = BN_get_word(p);
  double X_double = pow(2, gamma) / p_int;
  int X = (int)X_double;

  int *key = (int *)malloc(5 * sizeof(int));
  if (!key) {
    fprintf(stderr, "Memory allocation for key array failed\n");
  }
  // Populate key
  key[0] = p_int;
  key[1] = m_max;
  key[2] = X;
  key[3] = rho;
  key[4] = alpha;
  // Clean up
  BN_free(p);
  return key;
}