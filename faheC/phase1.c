#include <criterion/criterion.h>
#include <math.h>
#include <stdio.h>

#include "fahe.h"

// helpers
void debug_fahe_init(fahe_union *fahe, fahe_type type) {
  if (!fahe) {
    fprintf(stderr, "ERROR DEBUGGING: FAHE instance is NULL.\n");
    return;
  }

  if (type == FAHE1_TYPE) {
    fahe1 *fahe1_instance = &fahe->fahe1_instance;
    printf("FAHE1 Instance:\n");
    printf("lambda_param: %u\n", fahe1_instance->base.lambda_param);
    printf("m_max: %u\n", fahe1_instance->base.m_max);
    printf("alpha: %u\n", fahe1_instance->base.alpha);
    printf("msg_size: %u\n", fahe1_instance->base.msg_size);

    // Print num_additions
    char *num_additions_str = BN_bn2dec(fahe1_instance->num_additions);
    if (num_additions_str) {
      printf("num_additions: %s\n", num_additions_str);
      OPENSSL_free(num_additions_str);
    } else {
      fprintf(stderr, "Error converting num_additions to string\n");
    }

    // Print keys
    printf("key: ");
    for (int i = 0; i < 5; ++i) {
      printf("%d ", fahe1_instance->base.key[i]);
    }
    printf("\n");

    printf("enc_key: ");
    for (int i = 0; i < 4; ++i) {
      printf("%d ", fahe1_instance->base.enc_key[i]);
    }
    printf("\n");

    printf("dec_key: ");
    for (int i = 0; i < 4; ++i) {
      printf("%d ", fahe1_instance->base.dec_key[i]);
    }
    printf("\n");

  } else if (type == FAHE2_TYPE) {
    fahe2 *fahe2_instance = &fahe->fahe2_instance;
    printf("FAHE2 Instance:\n");
    printf("lambda_param: %u\n", fahe2_instance->base.lambda_param);
    printf("m_max: %u\n", fahe2_instance->base.m_max);
    printf("alpha: %u\n", fahe2_instance->base.alpha);
    printf("msg_size: %u\n", fahe2_instance->base.msg_size);

    // Print num_additions
    char *num_additions_str = BN_bn2dec(fahe2_instance->num_additions);
    if (num_additions_str) {
      printf("num_additions: %s\n", num_additions_str);
      OPENSSL_free(num_additions_str);
    } else {
      fprintf(stderr, "Error converting num_additions to string\n");
    }

    // Print keys
    printf("key: ");
    for (int i = 0; i < 5; ++i) {
      printf("%d ", fahe2_instance->base.key[i]);
    }
    printf("\n");

    printf("enc_key: ");
    for (int i = 0; i < 4; ++i) {
      printf("%d ", fahe2_instance->base.enc_key[i]);
    }
    printf("\n");

    printf("dec_key: ");
    for (int i = 0; i < 4; ++i) {
      printf("%d ", fahe2_instance->base.dec_key[i]);
    }
    printf("\n");

  } else {
    fprintf(stderr, "ERROR DEBUGGING: INVALID FAHE TYPE.\n");
  }
}

Test(fahe_fahe_init, fahe1_init00) {
  fahe_params params = {128, 32, 6, 32};
  fahe_union *fahe = fahe_init(&params, FAHE1_TYPE);
  debug_fahe_init(fahe, FAHE1_TYPE);
  fahe_free(fahe, FAHE1_TYPE);
}   