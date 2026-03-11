# ==============================================================================
# Makefile — libcaesar (задание 1) + secure_copy (задание 2)
# ==============================================================================

CXX      := g++
CXXFLAGS := -Wall -Wextra -pedantic -std=c++17 -fPIC

LIB_SRC  := caesar.cpp
LIB_OBJ  := caesar.o
LIB_NAME := libcaesar.so

TEST_SRC  := os_pr1.cpp
TEST_BIN  := os_pr1

COPY_SRC  := secure_copy.cpp
COPY_BIN  := secure_copy

INSTALL_DIR := /usr/local/lib

INPUT_FILE     := input.txt
ENCRYPTED_FILE := encrypted.bin
DECRYPTED_FILE := decrypted.txt
TEST_KEY       := 42

# ==============================================================================
# all: собрать всё
# ==============================================================================
.PHONY: all
all: $(LIB_NAME) $(TEST_BIN) $(COPY_BIN)

# Библиотека
$(LIB_NAME): $(LIB_OBJ)
	$(CXX) -shared -o $@ $^
	@echo "[OK] $(LIB_NAME) built."

$(LIB_OBJ): $(LIB_SRC) caesar.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Задание 1: тестовая программа
$(TEST_BIN): $(TEST_SRC) caesar.h
	$(CXX) $(CXXFLAGS) -o $@ $< -ldl
	@echo "[OK] $(TEST_BIN) built."

# Задание 2: secure_copy
# Линкуется с libcaesar.so через -L. -lcaesar и -pthread
$(COPY_BIN): $(COPY_SRC) caesar.h $(LIB_NAME)
	$(CXX) $(CXXFLAGS) -o $@ $< -L. -lcaesar -pthread -Wl,-rpath,.
	@echo "[OK] $(COPY_BIN) built."

# ==============================================================================
# install
# ==============================================================================
.PHONY: install
install: $(LIB_NAME)
	cp $(LIB_NAME) $(INSTALL_DIR)/$(LIB_NAME)
	ldconfig
	@echo "[OK] Installed to $(INSTALL_DIR)."

# ==============================================================================
# test: задание 1
# ==============================================================================
.PHONY: test
test: all
	@if [ ! -f $(INPUT_FILE) ]; then \
		echo "Hello, World! This is a test file for the libcaesar library." > $(INPUT_FILE); \
		echo "XOR encryption works with any binary data, not just text." >> $(INPUT_FILE); \
		echo "Applying caesar twice with the same key restores the original data." >> $(INPUT_FILE); \
		echo "The quick brown fox jumps over the lazy dog." >> $(INPUT_FILE); \
		echo "[INFO] Created $(INPUT_FILE)."; \
	fi
	@echo ""
	@echo "=== TEST 1: encryption ==="
	./$(TEST_BIN) ./$(LIB_NAME) $(TEST_KEY) $(INPUT_FILE) $(ENCRYPTED_FILE)
	@echo ""
	@echo "=== TEST 2: decryption ==="
	./$(TEST_BIN) ./$(LIB_NAME) $(TEST_KEY) $(ENCRYPTED_FILE) $(DECRYPTED_FILE)
	@echo ""
	@echo "=== TEST 3: XOR symmetry check ==="
	@if diff -q $(INPUT_FILE) $(DECRYPTED_FILE) > /dev/null 2>&1; then \
		echo "[PASS] Files match - XOR is symmetric!"; \
	else \
		echo "[FAIL] Files differ!"; exit 1; \
	fi
	@echo ""

# ==============================================================================
# test2: задание 2 — генерируем 1МБ файл и копируем через secure_copy
# ==============================================================================
.PHONY: test2
test2: all
	@echo "=== TEST secure_copy: generating 1MB test file ==="
	dd if=/dev/urandom of=big_input.bin bs=1024 count=1024 2>/dev/null
	@echo ""
	@echo "=== Encrypting with secure_copy ==="
	./$(COPY_BIN) big_input.bin big_encrypted.bin $(TEST_KEY)
	@echo ""
	@echo "=== Decrypting with secure_copy ==="
	./$(COPY_BIN) big_encrypted.bin big_decrypted.bin $(TEST_KEY)
	@echo ""
	@echo "=== Checking result ==="
	@if diff -q big_input.bin big_decrypted.bin > /dev/null 2>&1; then \
		echo "[PASS] Files match - secure_copy works correctly!"; \
	else \
		echo "[FAIL] Files differ!"; exit 1; \
	fi
	@echo ""

# ==============================================================================
# clean
# ==============================================================================
.PHONY: clean
clean:
	rm -f $(LIB_OBJ) $(LIB_NAME) $(TEST_BIN) $(COPY_BIN) \
	      $(ENCRYPTED_FILE) $(DECRYPTED_FILE) \
	      big_input.bin big_encrypted.bin big_decrypted.bin
	@echo "[OK] Cleaned."