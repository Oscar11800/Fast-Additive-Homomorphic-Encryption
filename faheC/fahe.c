#include <fahe.h>
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
    fahe1_instance->base.key_size = params->key_size;
    fahe1_instance->base.enc_key_size = params->enc_key_size;
    fahe1_instance->base.dec_key_size = params->dec_key_size;

    // Initialize num_additions for fahe1
    fahe1_instance->num_additions = BN_new();
    if (!fahe1_instance->num_additions) {
      fprintf(stderr, "Memory allocation for BIGNUM failed\n");
      free(fahe1_instance);
      exit(EXIT_FAILURE);
    }
    BN_one(fahe1_instance->num_additions);
    BN_lshift(fahe1_instance->num_additions, fahe1_instance->num_additions,
              (fahe1_instance->base.alpha) - 1);

    fahe = (fahe_base *)fahe1_instance;
  } else if (type == FAHE2_TYPE) {
    fahe2 *fahe2_instance = &fahe->fahe2_instance;

    // Initialize common params
    fahe2_instance->base.lambda_param = params->lambda_param;
    fahe2_instance->base.m_max = params->m_max;
    fahe2_instance->base.alpha = params->alpha;
    fahe2_instance->base.msg_size = params->msg_size;
    fahe2_instance->base.key_size = params->key_size;
    fahe2_instance->base.enc_key_size = params->enc_key_size;
    fahe2_instance->base.dec_key_size = params->dec_key_size;

  } else {
    fprintf(stderr, "Unknown type for fahe_init\n");
    free(fahe);
    exit(EXIT_FAILURE);
  }

  // Allocate memory for keys (for both fahe1 and fahe2)
  fahe_base *base = (type == FAHE1_TYPE) ? (fahe_base *)&fahe->fahe1_instance.base : (fahe_base *)&fahe->fahe2_instance.base;
  
  base->key = (int *)malloc(base->key_size * sizeof(int));
  if (!base->key) {
    fprintf(stderr, "Memory allocation for key failed\n");
    if (type == FAHE1_TYPE) {
      fahe1 *fahe1_instance = (fahe1 *)fahe;
      BN_free(fahe1_instance->num_additions);
    }
    free(fahe);
    exit(EXIT_FAILURE);
  }

  base->enc_key = (int *)malloc(base->enc_key_size * sizeof(int));
  if (!base->enc_key) {
    fprintf(stderr, "Memory allocation for enc_key failed\n");
    free(base->key);
    if (type == FAHE1_TYPE) {
      fahe1 *fahe1_instance = (fahe1 *)fahe;
      BN_free(fahe1_instance->num_additions);
    }
    free(fahe);
    exit(EXIT_FAILURE);
  }

  base->dec_key = (int *)malloc(base->dec_key_size * sizeof(int));
  if (!base->dec_key) {
    fprintf(stderr, "Memory allocation for dec_key failed\n");
    free(base->enc_key);
    free(base->key);
    if (type == FAHE1_TYPE) {
      fahe1 *fahe1_instance = (fahe1 *)fahe;
      BN_free(fahe1_instance->num_additions);
    }
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