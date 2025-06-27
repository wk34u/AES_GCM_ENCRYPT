#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>

#define TAG_LEN 16
#define BUFFER_SIZE 4096
#define MIN_KEYSOURCE_BYTES 16

void handleErrors(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

void derive_key_iv(const char *filename, unsigned char *key, unsigned char *iv) {
    FILE *f = fopen(filename, "rb");
    if (!f) handleErrors("Failed to open key source file");

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    if (size < MIN_KEYSOURCE_BYTES)
        handleErrors("Key source file too short. Minimum 16 bytes required.");

    unsigned char buffer[BUFFER_SIZE];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL) != 1)
        handleErrors("EVP_DigestInit_ex failed");

    size_t len;
    while ((len = fread(buffer, 1, BUFFER_SIZE, f)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, len) != 1)
            handleErrors("EVP_DigestUpdate failed");
    }
    fclose(f);

    unsigned char hash[SHA512_DIGEST_LENGTH];
    unsigned int md_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &md_len) != 1)
        handleErrors("EVP_DigestFinal_ex failed");

    EVP_MD_CTX_free(mdctx);

    memcpy(key, hash, 32);
    memcpy(iv,  hash + 32, 12);
}

int encrypt_fp(FILE *fin, FILE *fout, const unsigned char *key, const unsigned char *iv) {
    OSSL_PROVIDER_load(NULL, "default");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("EVP_CIPHER_CTX_new failed");

    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (!cipher) handleErrors("EVP_CIPHER_fetch AES-256-GCM failed");

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
        handleErrors("EncryptInit step 1 failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        handleErrors("Set IV length failed");

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        handleErrors("EncryptInit step 2 failed");

    EVP_CIPHER_free(cipher);

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + TAG_LEN];
    size_t inlen = 0, total_read = 0;
    int outlen = 0;

    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, fin)) > 0) {
        total_read += inlen;
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)inlen) != 1)
            handleErrors("EncryptUpdate failed");
        fwrite(outbuf, 1, outlen, fout);
    }

    if (total_read == 0) {
        const unsigned char dummy = 0x00;
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, &dummy, 1) != 1)
            handleErrors("EncryptUpdate failed for dummy input");
        fwrite(outbuf, 1, outlen, fout);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1)
        handleErrors("EncryptFinal failed");
    fwrite(outbuf, 1, outlen, fout);

    unsigned char tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        handleErrors("Get tag failed");
    fwrite(tag, 1, TAG_LEN, fout);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int decrypt_fp(FILE *fin, FILE *fout, const unsigned char *key, const unsigned char *iv) {
    fseek(fin, 0, SEEK_END);
    long total_size = ftell(fin);
    if (total_size < TAG_LEN) handleErrors("Encrypted file too small");

    long ciphertext_len = total_size - TAG_LEN;
    fseek(fin, ciphertext_len, SEEK_SET);
    unsigned char tag[TAG_LEN];
    fread(tag, 1, TAG_LEN, fin);
    rewind(fin);

    OSSL_PROVIDER_load(NULL, "default");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("EVP_CIPHER_CTX_new failed");

    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (!cipher) handleErrors("EVP_CIPHER_fetch AES-256-GCM failed");

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
        handleErrors("DecryptInit step 1 failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        handleErrors("Set IV length failed");

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        handleErrors("DecryptInit step 2 failed");

    EVP_CIPHER_free(cipher);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1)
        handleErrors("Set tag failed");

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE];
    int inlen, outlen;
    long read_total = 0;

    while (read_total < ciphertext_len) {
        long to_read = (ciphertext_len - read_total > BUFFER_SIZE) ? BUFFER_SIZE : (ciphertext_len - read_total);
        inlen = fread(inbuf, 1, to_read, fin);
        if (inlen <= 0) break;
        read_total += inlen;

        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1)
            handleErrors("DecryptUpdate failed");

        if (!(ciphertext_len == 1 && outlen == 1 && outbuf[0] == 0x00))
            fwrite(outbuf, 1, outlen, fout);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1)
        handleErrors("DecryptFinal failed: authentication failed");

    fwrite(outbuf, 1, outlen, fout);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int encrypt(const char *infile, const char *outfile, const unsigned char *key, const unsigned char *iv) {
    FILE *fin = fopen(infile, "rb");
    FILE *fout = fopen(outfile, "wb");
    if (!fin || !fout) handleErrors("Failed to open input/output file");
    int result = encrypt_fp(fin, fout, key, iv);
    fclose(fin);
    fclose(fout);
    return result;
}

int decrypt(const char *infile, const char *outfile, const unsigned char *key, const unsigned char *iv) {
    FILE *fin = fopen(infile, "rb");
    FILE *fout = fopen(outfile, "wb");
    if (!fin || !fout) handleErrors("Failed to open input/output file");
    int result = decrypt_fp(fin, fout, key, iv);
    fclose(fin);
    fclose(fout);
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <enc|dec> <input_file> <output_file> <keysource_file>\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *infile = argv[2];
    const char *outfile = argv[3];
    const char *keysource = argv[4];

    unsigned char key[32], iv[12];
    derive_key_iv(keysource, key, iv);

    int same_file = (strcmp(infile, outfile) == 0);
    int result = 1;

    if (same_file) {
        FILE *fin = fopen(infile, "rb");
        FILE *tmp = tmpfile();
        if (!fin || !tmp) handleErrors("Failed to open files");

        if (strcmp(mode, "enc") == 0)
            result = encrypt_fp(fin, tmp, key, iv);
        else if (strcmp(mode, "dec") == 0)
            result = decrypt_fp(fin, tmp, key, iv);
        else
            handleErrors("Invalid mode");

        fclose(fin);

        if (result == 0) {
            rewind(tmp);
            FILE *fout = fopen(outfile, "wb");
            if (!fout) handleErrors("Failed to reopen output file");

            unsigned char buf[BUFFER_SIZE];
            size_t len;
            while ((len = fread(buf, 1, BUFFER_SIZE, tmp)) > 0)
                fwrite(buf, 1, len, fout);

            fclose(fout);
        }

        fclose(tmp);
    } else {
        if (strcmp(mode, "enc") == 0) {
            result = encrypt(infile, outfile, key, iv);
        } else if (strcmp(mode, "dec") == 0) {
            result = decrypt(infile, outfile, key, iv);
        } else {
            fprintf(stderr, "Invalid mode: %s. Use 'enc' or 'dec'.\n", mode);
            return 1;
        }
    }

    return result;
}
