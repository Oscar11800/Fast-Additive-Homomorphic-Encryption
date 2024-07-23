#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static pthread_mutex_t *lock_cs;

void locking_function(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&lock_cs[n]);
    } else {
        pthread_mutex_unlock(&lock_cs[n]);
    }
}

unsigned long id_function(void) {
    return (unsigned long)pthread_self();
}

void thread_setup(void) {
    int i;

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
}

void thread_cleanup(void) {
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&(lock_cs[i]));
    }

    OPENSSL_free(lock_cs);
}