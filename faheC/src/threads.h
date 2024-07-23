#include <openssl/bn.h>

typedef struct {
    BIGNUM *p;
    int m_max;
    int rho;
    int alpha;
    BIGNUM **ciphertext_list;
    int start;
    int end;
    BIGNUM **decrypted_list;
} DecThreadData;

typedef struct {
    BIGNUM *p;
    BIGNUM *X;
    int rho;
    int alpha;
    BIGNUM **message_list;
    int start;
    int end;
    BIGNUM **ciphertext_list;
} EncThreadData;

void thread_setup(void);
void thread_teardown(void);

void locking_function(int mode, int n, const char *file, int line);
unsigned long id_function(void);
void thread_setup(void);
void thread_teardown(void);