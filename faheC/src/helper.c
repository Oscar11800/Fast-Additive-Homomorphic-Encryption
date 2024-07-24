#include <math.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fahe1.h"
#include "fahe2.h"
#include "logger.h"

BIGNUM *rand_num_below(const BIGNUM *upper_bound) {
  BIGNUM *rand_bn = BN_new();
  if (!rand_bn) {
    log_message(LOG_FATAL, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }

  if (!BN_rand_range(rand_bn, upper_bound)) {
    log_message(LOG_FATAL, "BN_rand_range failed\n");
    BN_free(rand_bn);
    exit(EXIT_FAILURE);
  }

  return rand_bn;
}

BIGNUM *rand_bits_below(unsigned int bitlength) {
  BIGNUM *rand_bn = BN_new();
  if (!rand_bn) {
    log_message(LOG_FATAL, "BN_new failed\n");
    exit(EXIT_FAILURE);
  }

  if (!BN_rand(rand_bn, bitlength, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
    log_message(LOG_FATAL, "BN_rand failed\n");
    BN_free(rand_bn);
    exit(EXIT_FAILURE);
  }

  return rand_bn;
}

BIGNUM *generate_big_message(unsigned int message_size) {
  BIGNUM *BN_message = BN_new();
  if (!BN_message) {
    log_message(LOG_FATAL, "BNmessage failed\n");
    BN_free(BN_message);
    exit(EXIT_FAILURE);
  }

  // Generate a random number of `message_size` bits
  if (!BN_rand(BN_message, message_size, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
    log_message(LOG_FATAL, "BNmessage failed\n");
    BN_free(BN_message);
    exit(EXIT_FAILURE);
  }

  return BN_message;
}

BIGNUM **generate_message_list(unsigned int message_size,
                               BIGNUM *num_messages) {
  BIGNUM **message_list =
      (BIGNUM **)malloc(BN_get_word(num_messages) * sizeof(BIGNUM *));
  if (!message_list) {
    log_message(LOG_FATAL, "message_list allocation failed\n");
    exit(EXIT_FAILURE);
  }

  for (unsigned int i = 0; i < BN_get_word(num_messages); i++) {
    message_list[i] = generate_big_message(message_size);
    if (!message_list[i]) {
      log_message(LOG_FATAL, "generate_big_message failed for message %u\n", i);
      // Free previously allocated BIGNUMs
      for (unsigned int j = 0; j < i; j++) {
        BN_free(message_list[j]);
      }
      free(message_list);
      exit(EXIT_FAILURE);
    }
  }

  log_message(LOG_INFO, "Message List Successfully generated");
  return message_list;
}

void free_message_list(BIGNUM **message_list, int list_size) {
    for (int i = 0; i < list_size; i++) {
        BN_free(message_list[i]);
    }
    free(message_list);
}

unsigned int bit_length(uint64_t num) {
  unsigned int length = 0;
  while (num > 0) {
    num >>= 1;
    length++;
  }
  return length == 0 ? 1 : length;
}

void debug_fahe1_init(fahe1 *fahe1_instance) {
  if (!fahe1_instance) {
    fprintf(stderr, "ERROR DEBUGGING: FAHE instance is NULL.\n");
    return;
  }
  printf("FAHE1 Instance:\n");
  printf("lambda: %d\n", fahe1_instance->key.lambda);
  printf("m_max: %d\n", fahe1_instance->key.m_max);
  printf("alpha: %d\n", fahe1_instance->key.alpha);
  printf("msg_size: %u\n", fahe1_instance->msg_size);

  // Print num_additions
  char *num_additions_str = BN_bn2dec(fahe1_instance->num_additions);
  if (num_additions_str) {
    printf("num_additions: %s\n", num_additions_str);
    OPENSSL_free(num_additions_str);
  } else {
    fprintf(stderr, "Error converting num_additions to string\n");
  }
}

void debug_fahe2_init(fahe2 *fahe2_instance) {
  if (!fahe2_instance) {
    fprintf(stderr, "ERROR DEBUGGING: FAHE instance is NULL.\n");
    return;
  }
  printf("FAHE2 Instance:\n");
  printf("lambda: %d\n", fahe2_instance->key.lambda);
  printf("m_max: %d\n", fahe2_instance->key.m_max);
  printf("alpha: %d\n", fahe2_instance->key.alpha);
  printf("msg_size: %u\n", fahe2_instance->msg_size);

  // Print num_additions
  char *num_additions_str = BN_bn2dec(fahe2_instance->num_additions);
  if (num_additions_str) {
    printf("num_additions: %s\n", num_additions_str);
    OPENSSL_free(num_additions_str);
  } else {
    fprintf(stderr, "Error converting num_additions to string\n");
  }
}

// Helper function to print a BIGNUM
void print_bn(const char *label, BIGNUM *bn) {
  char *bn_str = BN_bn2dec(bn);
  if (bn_str) {
    fprintf(stdout, "%s: %s\n", label, bn_str);
    OPENSSL_free(bn_str);  // Free the allocated string
  } else {
    fprintf(stderr, "Error converting BIGNUM to decimal string\n");
  }
}

void print_bn_list(const char *label, BIGNUM **bn_list, unsigned int len) {
  for (unsigned int i = 0; i < len; i++) {
    char *bn_str = BN_bn2dec(bn_list[i]);
    if (bn_str) {
      fprintf(stdout, "%s[%u]: %s\n", label, i, bn_str);
      OPENSSL_free(bn_str);
    } else {
      fprintf(stderr, "Error converting BIGNUM to decimal string at index %u\n",
              i);
    }
  }
}

void write_messages_to_file(BIGNUM **message_list, unsigned int num_msgs,
                            const char *filename) {
  FILE *file = fopen(filename, "w");
  if (!file) {
    fprintf(stderr, "Failed to open file for writing\n");
    exit(EXIT_FAILURE);
  }

  for (unsigned int i = 0; i < num_msgs; i++) {
    char *msg_str = BN_bn2dec(message_list[i]);
    if (msg_str) {
      fprintf(file, "%s", msg_str);
      if (i < num_msgs - 1) {
        fprintf(file, ",");
      }
      OPENSSL_free(msg_str);
    } else {
      log_message(LOG_FATAL, "Error converting BIGNUM to string\n");
      fclose(file);
      exit(EXIT_FAILURE);
    }
  }

  fclose(file);
}

BIGNUM **read_bignum_list_from_file(const char *filename, int *num_elements) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    fprintf(stderr, "Failed to open file %s for reading\n", filename);
    return NULL;
  }

  // Read the file content into a string
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  char *file_content = (char *)malloc(file_size + 1);
  if (!file_content) {
    fprintf(stderr, "Memory allocation failed\n");
    fclose(file);
    return NULL;
  }

  fread(file_content, 1, file_size, file);
  file_content[file_size] = '\0';
  fclose(file);

  // Count the number of elements
  *num_elements = 1;  // There's at least one number
  for (char *p = file_content; *p; p++) {
    if (*p == ',') {
      (*num_elements)++;
    }
  }

  // Allocate memory for the BIGNUM list
  BIGNUM **bignum_list = (BIGNUM **)malloc(*num_elements * sizeof(BIGNUM *));
  if (!bignum_list) {
    fprintf(stderr, "Memory allocation failed\n");
    free(file_content);
    return NULL;
  }

  // Split the file content by commas and convert to BIGNUMs
  char *token = strtok(file_content, ",");
  int index = 0;
  while (token) {
    bignum_list[index] = BN_new();
    if (!bignum_list[index]) {
      fprintf(stderr, "BN_new failed\n");
      // Free previously allocated BIGNUMs
      for (int j = 0; j < index; j++) {
        BN_free(bignum_list[j]);
      }
      free(bignum_list);
      free(file_content);
      return NULL;
    }

    if (!BN_dec2bn(&bignum_list[index], token)) {
      fprintf(stderr, "BN_dec2bn failed for token %s\n", token);
      // Free previously allocated BIGNUMs
      for (int j = 0; j < index; j++) {
        BN_free(bignum_list[j]);
      }
      BN_free(bignum_list[index]);
      free(bignum_list);
      free(file_content);
      return NULL;
    }

    token = strtok(NULL, ",");
    index++;
  }

  free(file_content);
  return bignum_list;
}