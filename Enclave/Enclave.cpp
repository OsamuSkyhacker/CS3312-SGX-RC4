#include "Enclave_t.h"
#include <string.h> // for memcpy


int secret_print_helloworld() {
    ocall_print("I Love SJTU");
    return 1896;
}


// RC4 状态结构
struct rc4_state {
    unsigned char S[256];
    int i, j;
};

static rc4_state state;

// KSA: 密钥调度算法
void rc4_init(const unsigned char *key, size_t len) {
    int i, j;
    unsigned char t;

    for (i = 0; i < 256; i++) {
        state.S[i] = (unsigned char)i;
    }

    for (i = 0, j = 0; i < 256; i++) {
        j = (j + state.S[i] + key[i % len]) % 256;
        t = state.S[i];
        state.S[i] = state.S[j];
        state.S[j] = t;
    }

    state.i = 0;
    state.j = 0;
}

// PRGA: 伪随机生成算法
void rc4_crypt(unsigned char *data, size_t len) {
    int i = state.i, j = state.j;
    unsigned char t;

    for (size_t k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + state.S[i]) % 256;
        t = state.S[i];
        state.S[i] = state.S[j];
        state.S[j] = t;
        data[k] ^= state.S[(state.S[i] + state.S[j]) % 256];
    }

    state.i = i;
    state.j = j;
}