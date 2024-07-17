#include "fahe.h"

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

    // Generate the key1
    fahe1_instance->base.key1 =
        fahe1_keygen(params->lambda, params->m_max, params->alpha);
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
              (fahe1_instance->base.key1.alpha) - 1);

    // Initialize enc_key and dec_key
    fahe1_instance->base.enc_key = (int *)malloc(4 * sizeof(int));
    fahe1_instance->base.dec_key = (int *)malloc(4 * sizeof(int));
    if (!fahe1_instance->base.enc_key || !fahe1_instance->base.dec_key) {
      fprintf(stderr, "Memory allocation for enc_key or dec_key failed\n");
      BN_free(fahe1_instance->base.key1.p);
      BN_free(fahe1_instance->base.key1.X);
      free(fahe1_instance->base.enc_key);
      free(fahe1_instance->base.dec_key);
      free(fahe);
      exit(EXIT_FAILURE);
    }

    fahe1_instance->base.enc_key[0] = BN_get_word(fahe1_instance->base.key1.p);
    fahe1_instance->base.enc_key[1] = BN_get_word(fahe1_instance->base.key1.X);
    fahe1_instance->base.enc_key[2] = fahe1_instance->base.key1.lambda;
    fahe1_instance->base.enc_key[3] = fahe1_instance->base.key1.alpha;

    fahe1_instance->base.dec_key[0] = BN_get_word(fahe1_instance->base.key1.p);
    fahe1_instance->base.dec_key[1] = fahe1_instance->base.key1.m_max;
    fahe1_instance->base.dec_key[2] = fahe1_instance->base.key1.lambda;
    fahe1_instance->base.dec_key[3] = fahe1_instance->base.key1.alpha;
  } else if (type == FAHE2_TYPE) {
    fahe2 *fahe2_instance = &fahe->fahe2_instance;

    // Generate the key1
    fahe2_instance->base.key2 =
        fahe2_keygen(params->lambda, params->m_max, params->alpha);
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
              (fahe2_instance->base.key2.alpha) - 1);

    // Initialize enc_key and dec_key
    fahe2_instance->base.enc_key = (int *)malloc(4 * sizeof(int));
    fahe2_instance->base.dec_key = (int *)malloc(4 * sizeof(int));
    if (!fahe2_instance->base.enc_key || !fahe2_instance->base.dec_key) {
      fprintf(stderr, "Memory allocation for enc_key or dec_key failed\n");
      BN_free(fahe2_instance->base.key2.p);
      free(fahe2_instance->base.enc_key);
      free(fahe2_instance->base.dec_key);
      free(fahe);
      exit(EXIT_FAILURE);
    }

    fahe2_instance->base.enc_key[0] = BN_get_word(fahe2_instance->base.key2.p);
    fahe2_instance->base.enc_key[1] = fahe2_instance->base.key2.X;
    fahe2_instance->base.enc_key[2] = fahe2_instance->base.key2.lambda;
    fahe2_instance->base.enc_key[3] = fahe2_instance->base.key2.alpha;
    fahe2_instance->base.dec_key[0] = BN_get_word(fahe2_instance->base.key2.p);
    fahe2_instance->base.dec_key[1] = fahe2_instance->base.key2.m_max;
    fahe2_instance->base.dec_key[2] = fahe2_instance->base.key2.lambda;
    fahe2_instance->base.dec_key[3] = fahe2_instance->base.key2.alpha;
  } else {
    fprintf(stderr, "Unknown type for fahe_init\n");
    free(fahe);
    exit(EXIT_FAILURE);
  }
  return fahe;
}

void fahe_free(fahe_union *fahe, fahe_type type) {
  if (!fahe) return;

  fahe_base *base = (type == FAHE1_TYPE)
                        ? (fahe_base *)&fahe->fahe1_instance.base
                        : (fahe_base *)&fahe->fahe2_instance.base;

  // Free the key1 BIGNUM
  if (base->key1.p) {
    BN_free(base->key1.p);
  }

  // Free the key1 arrays
  if (base->enc_key) {
    free(base->enc_key);
  }
  if (base->dec_key) {
    free(base->dec_key);
  }

  if (type == FAHE1_TYPE) {
    if (fahe->fahe1_instance.num_additions) {
      BN_free(fahe->fahe1_instance.num_additions);
    }
  } else if (type == FAHE2_TYPE) {
    if (fahe->fahe2_instance.num_additions) {
      BN_free(fahe->fahe2_instance.num_additions);
    }
  }

  // Free the union itself
  free(fahe);
}

fahe1_key fahe1_keygen(int lambda, int m_max, int alpha) {
  fahe1_key key1;

  key1.lambda = lambda;
  key1.m_max = m_max;
  key1.alpha = alpha;

  int rho = lambda;
  key1.rho = rho;
  double eta = rho + (2 * alpha) + m_max;
  int gamma = (int)(rho / log2(rho) * ((eta - rho) * (eta - rho)));
  // Generate a large prime p
  key1.p = BN_new();
  if (!key1.p) {
    fprintf(stderr, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }
  if (!BN_generate_prime_ex(key1.p, (int)eta, 1, NULL, NULL, NULL)) {
    fprintf(stderr, "BN_generate_prime_ex failed\n");
    BN_free(key1.p);
    exit(EXIT_FAILURE);
  }
  printf("p decimal: %s\n", BN_bn2dec(key1.p));

  // Calculate X = (2^gamma) / p using BIGNUM
  BIGNUM *X = BN_new();
  BIGNUM *base = BN_new();
  BIGNUM *gamma_bn = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!X || !base || !gamma_bn || !ctx) {
    fprintf(stderr, "BN_new or BN_CTX_new failed\n");
    BN_free(key1.p);
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
    fprintf(stderr, "BN_exp failed\n");
    BN_free(key1.p);
    BN_free(X);
    BN_free(base);
    BN_free(gamma_bn);
    BN_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // Divide 2^gamma by p
  if (!BN_div(X, NULL, X, key1.p, ctx)) {
    fprintf(stderr, "BN_div failed\n");
    BN_free(key1.p);
    BN_free(X);
    BN_free(base);
    BN_free(gamma_bn);
    BN_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // Convert X to int
  key1.X = X;

  // Clean up
  BN_free(X);
  BN_free(base);
  BN_free(gamma_bn);
  BN_CTX_free(ctx);

  return key1;
}

fahe2_key fahe2_keygen(int lambda, int m_max, int alpha) {
  fahe2_key key1;

  key1.lambda = lambda;
  key1.m_max = m_max;
  key1.alpha = alpha;

  int rho = lambda + alpha + m_max;
  int eta = rho + alpha;
  int gamma = (int)(rho / log2(rho) * ((eta - rho) * (eta - rho)));

  // Generate a large prime p
  key1.p = BN_new();
  if (!key1.p) {
    fprintf(stderr, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }
  if (!BN_generate_prime_ex(key1.p, (int)eta, 1, NULL, NULL, NULL)) {
    fprintf(stderr, "BN_generate_prime_ex failed\n");
    BN_free(key1.p);
    exit(EXIT_FAILURE);
  }

  char *p_str = BN_bn2dec(key1.p);
  if (!p_str) {
    fprintf(stderr, "BN_bn2dec failed\n");
    BN_free(key1.p);
    exit(EXIT_FAILURE);
  }
  double p_double = atof(p_str);
  double X_double = pow(2, gamma) / p_double;
  key1.X = (int)X_double;
  int pos = 120;
  key1.pos = pos;
  return key1;
}
