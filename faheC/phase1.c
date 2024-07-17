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
    printf("lambda: %d\n", fahe1_instance->base.key1.lambda);
    printf("m_max: %d\n", fahe1_instance->base.key1.m_max);
    printf("alpha: %d\n", fahe1_instance->base.key1.alpha);
    printf("msg_size: %u\n", fahe1_instance->base.msg_size);

    // Print num_additions
    char *num_additions_str = BN_bn2dec(fahe1_instance->num_additions);
    if (num_additions_str) {
      printf("num_additions: %s\n", num_additions_str);
      OPENSSL_free(num_additions_str);
    } else {
      fprintf(stderr, "Error converting num_additions to string\n");
    }

  } else if (type == FAHE2_TYPE) {
    fahe2 *fahe2_instance = &fahe->fahe2_instance;
    printf("FAHE2 Instance:\n");
    printf("lambda: %d\n", fahe2_instance->base.key2.lambda);
    printf("m_max: %d\n", fahe2_instance->base.key2.m_max);
    printf("alpha: %d\n", fahe2_instance->base.key2.alpha);
    printf("X: %d\n", fahe2_instance->base.key2.X);
    printf("rho: %d\n", fahe2_instance->base.key2.rho);
    printf("pos: %d\n", fahe2_instance->base.key2.pos);
    printf("msg_size: %u\n", fahe2_instance->base.msg_size);

    // Print num_additions
    char *num_additions_str = BN_bn2dec(fahe2_instance->num_additions);
    if (num_additions_str) {
      printf("num_additions: %s\n", num_additions_str);
      OPENSSL_free(num_additions_str);
    } else {
      fprintf(stderr, "Error converting num_additions to string\n");
    }

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