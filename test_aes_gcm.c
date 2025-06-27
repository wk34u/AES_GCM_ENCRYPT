#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BUFFER_SIZE 4096

int run_cmd(const char *cmd) {
    int ret = system(cmd);
    if (ret != 0) printf("Command failed: %s\n", cmd);
    return ret;
}

int compare_files(const char *f1, const char *f2) {
    FILE *a = fopen(f1, "rb");
    FILE *b = fopen(f2, "rb");
    if (!a || !b) return 0;

    int result = 1;
    while (1) {
        int c1 = fgetc(a);
        int c2 = fgetc(b);
        if (c1 != c2) {
            result = 0;
            break;
        }
        if (c1 == EOF || c2 == EOF) break;
    }
    fclose(a);
    fclose(b);
    return result;
}

void write_file(const char *filename, const void *data, size_t len) {
    FILE *f = fopen(filename, "wb");
    fwrite(data, 1, len, f);
    fclose(f);
}

int test_case(const char *label, const void *input_data, size_t input_len, const void *key_data, size_t key_len) {
    printf("== Test: %s ==\n", label);
    write_file("in.txt", input_data, input_len);
    write_file("key.bin", key_data, key_len);

    if (run_cmd("aes_gcm_encrypt.exe enc in.txt out.enc key.bin")) return 1;
    if (run_cmd("aes_gcm_encrypt.exe dec out.enc out.txt key.bin")) return 1;

    int match = compare_files("in.txt", "out.txt");
    printf("%s\n\n", match ? "PASS" : "FAIL");
    return match ? 0 : 1;
}

int main() {
    int failed = 0;

    const unsigned char short_key[] = "shortshortshort!"; // 16 bytes
    const unsigned char good_key[] = "0123456789ABCDEF0123456789ABCDEFkey"; // >= 32 bytes
    const unsigned char long_key[4096] = { [0 ... 4095] = 'K' };
    unsigned char buffer[1024 * 1024]; // buffer for large/random input

    // Original tests
    failed += test_case("Empty input, short key", "", 0, short_key, sizeof(short_key));
    failed += test_case("1-byte input, short key", "A", 1, short_key, sizeof(short_key));
    failed += test_case("Short input, long key", "Test data!", 10, long_key, sizeof(long_key));
    failed += test_case("Large input, long key", long_key, 1024, long_key, sizeof(long_key));
    failed += test_case("Multiblock input (4100 bytes)", long_key, 4100, good_key, sizeof(good_key));

    // New tests
    failed += test_case("Exact block (16 bytes)", "0123456789ABCDEF", 16, good_key, sizeof(good_key));

    const char block48[48] = { [0 ... 47] = 'A' };
    failed += test_case("Multi-block aligned (48 bytes)", block48, sizeof(block48), good_key, sizeof(good_key));

    const char block17[17] = "0123456789ABCDEFQ";
    failed += test_case("Unaligned block (17 bytes)", block17, sizeof(block17), good_key, sizeof(good_key));

    const unsigned char min_valid_key[16] = "1234567890ABCDEF";
    failed += test_case("Minimum valid key (16 bytes)", "hello", 5, min_valid_key, sizeof(min_valid_key));

    memset(buffer, 'Z', BUFFER_SIZE - 1);
    failed += test_case("Buffer limit - 1", buffer, BUFFER_SIZE - 1, good_key, sizeof(good_key));

    for (size_t i = 0; i < 128; ++i) buffer[i] = rand() % 256;
    failed += test_case("Random input (128 bytes)", buffer, 128, good_key, sizeof(good_key));

    memset(buffer, 'X', 1024 * 1024);
    failed += test_case("Large file (1MB)", buffer, 1024 * 1024, good_key, sizeof(good_key));

    failed += test_case("Huge key (4KB)", "data", 4, long_key, sizeof(long_key));

    if (failed == 0) {
        printf("All tests passed.\n");
    } else {
        printf("Some tests failed (%d failures).\n", failed);
    }

    return failed;
}
