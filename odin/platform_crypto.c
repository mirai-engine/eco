#include <stdint.h>
#include <stdlib.h>

#ifdef ECO_LIBCRYPTO
#include <dlfcn.h>
#include <openssl/evp.h>

static struct {
    int resolved;
    const EVP_CIPHER *(*aes_gcm)(void);
    EVP_CIPHER_CTX *(*create)(void);
    void (*destroy)(EVP_CIPHER_CTX *);
    int (*init)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned char *,
                const unsigned char *, int);
    int (*update)(EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int);
    int (*final)(EVP_CIPHER_CTX *, unsigned char *, int *);
    int (*control)(EVP_CIPHER_CTX *, int, int, void *);
} api;

static int load_api(void) {
    if (api.resolved) return api.resolved > 0;
    api.resolved = -1;
    void *library = dlopen(ECO_LIBCRYPTO, RTLD_LOCAL | RTLD_NOW);
    if (!library) return 0;
    api.aes_gcm = dlsym(library, "EVP_aes_256_gcm");
    api.create = dlsym(library, "EVP_CIPHER_CTX_new");
    api.destroy = dlsym(library, "EVP_CIPHER_CTX_free");
    api.init = dlsym(library, "EVP_CipherInit_ex");
    api.update = dlsym(library, "EVP_CipherUpdate");
    api.final = dlsym(library, "EVP_CipherFinal_ex");
    api.control = dlsym(library, "EVP_CIPHER_CTX_ctrl");
    if (!api.aes_gcm || !api.create || !api.destroy || !api.init ||
        !api.update || !api.final || !api.control) {
        dlclose(library);
        return 0;
    }
    api.resolved = 1;
    return 1;
}

void *eco_aes_context(const uint8_t *key, int encrypt) {
    if (!load_api()) return NULL;
    EVP_CIPHER_CTX *ctx = api.create();
    if (ctx && api.init(ctx, api.aes_gcm(), NULL, key, NULL, encrypt) != 1) {
        api.destroy(ctx);
        return NULL;
    }
    return ctx;
}

void eco_aes_free(void *ctx) {
    if (ctx) api.destroy(ctx);
}

int eco_aes_record(void *ctx, const uint8_t *nonce, const uint8_t *aad, int aad_len,
                   uint8_t *text, int count, uint8_t *tag, int encrypt) {
    int bytes, final;
    unsigned char block[16];
    if (api.init(ctx, NULL, NULL, NULL, nonce, -1) != 1 ||
        api.update(ctx, NULL, &bytes, aad, aad_len) != 1 ||
        api.update(ctx, text, &bytes, text, count) != 1 || bytes != count) return 0;
    if (!encrypt && api.control(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) return 0;
    if (api.final(ctx, block, &final) != 1 || final != 0) return 0;
    return !encrypt || api.control(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
}
#else
void *eco_aes_context(const uint8_t *key, int encrypt) { (void)key; (void)encrypt; return NULL; }
void eco_aes_free(void *ctx) { (void)ctx; }
int eco_aes_record(void *ctx, const uint8_t *nonce, const uint8_t *aad, int aad_len,
                   uint8_t *text, int count, uint8_t *tag, int encrypt) {
    (void)ctx; (void)nonce; (void)aad; (void)aad_len; (void)text; (void)count; (void)tag; (void)encrypt;
    return 0;
}
#endif
