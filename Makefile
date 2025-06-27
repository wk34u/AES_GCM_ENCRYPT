# 编译器
CC = gcc

# 主程序和测试程序
TARGET = aes_gcm_encrypt
TEST = test_aes_gcm

# 源文件
SRC = aes_gcm_encrypt.c
TEST_SRC = test_aes_gcm.c

# 包含路径
CFLAGS = -I./openssl/include

# 库路径和链接库
LDFLAGS = -L./openssl/lib64
LDLIBS = -lssl -lcrypto -lcrypt32 -lws2_32 -lgdi32 -luser32 -ladvapi32

# 默认构建
all: $(TARGET) $(TEST)

# 构建主程序
$(TARGET): $(SRC)
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS) $(LDLIBS)

# 构建测试程序
$(TEST): $(TEST_SRC)
	$(CC) $< -o $@ $(CFLAGS)

# 清理
clean:
	rm -f $(TARGET) $(TEST) *.o *.txt *.bin
