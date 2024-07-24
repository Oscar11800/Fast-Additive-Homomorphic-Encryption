#include <criterion/criterion.h>
#include <math.h>
#include <stdio.h>

#include "fahe2.h"
#include "helper.h"
#include "logger.h"

// Phase 1 Tests --------------

// arg 1: name of test suite, arg 2: test name
Test(fahe2, fahe2_init) {
  fahe_params params = {128, 32, 6, 32};
  fahe2 *fahe2_instance = fahe2_init(&params);
  debug_fahe2_init(fahe2_instance);
  fahe2_free(fahe2_instance);
}