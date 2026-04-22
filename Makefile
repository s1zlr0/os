CXX      := g++
CXXFLAGS := -Wall -Wextra -pedantic -std=c++17 -fPIC

LIB_SRC  := caesar.cpp
LIB_OBJ  := caesar.o
LIB_NAME := libcaesar.so

TEST_SRC  := os_pr1.cpp
TEST_BIN  := os_pr1

COPY_SRC     := secure_copy.cpp
COPY_BIN     := secure_copy
WORKERS_COUNT := 4

STAGE1_BIN := secure_copy_stage1
STAGE2_BIN := secure_copy_stage2
STAGE3_BIN := secure_copy_stage3
STAGE4_BIN := secure_copy_stage4
STAGE5_BIN := secure_copy_stage5

INSTALL_DIR := /usr/local/lib

INPUT_FILE     := input.txt
ENCRYPTED_FILE := encrypted.bin
DECRYPTED_FILE := decrypted.txt
TEST_KEY       := 42

.PHONY: all
all: $(LIB_NAME) $(TEST_BIN) $(COPY_BIN) $(STAGE1_BIN) $(STAGE2_BIN) $(STAGE3_BIN) $(STAGE4_BIN) $(STAGE5_BIN)

$(LIB_NAME): $(LIB_OBJ)
	$(CXX) -shared -o $@ $^
	@echo "[OK] $(LIB_NAME) built."

$(LIB_OBJ): $(LIB_SRC) caesar.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(TEST_BIN): $(TEST_SRC) caesar.h
	$(CXX) $(CXXFLAGS) -o $@ $< -ldl
	@echo "[OK] $(TEST_BIN) built."

$(COPY_BIN): $(COPY_SRC) caesar.h $(LIB_NAME)
	$(CXX) $(CXXFLAGS) -DWORKERS_COUNT=$(WORKERS_COUNT) -o $@ $< -L. -lcaesar -pthread -Wl,-rpath,.
	@echo "[OK] $(COPY_BIN) built."

$(STAGE1_BIN): secure_copy_stage1.cpp caesar.h $(LIB_NAME)
	$(CXX) $(CXXFLAGS) -o $@ $< -L. -lcaesar -pthread -Wl,-rpath,.
	@echo "[OK] $(STAGE1_BIN) built."

$(STAGE2_BIN): secure_copy_stage2.cpp caesar.h $(LIB_NAME)
	$(CXX) $(CXXFLAGS) -o $@ $< -L. -lcaesar -pthread -Wl,-rpath,.
	@echo "[OK] $(STAGE2_BIN) built."

$(STAGE3_BIN): secure_copy_stage3.cpp caesar.h $(LIB_NAME)
	$(CXX) $(CXXFLAGS) -o $@ $< -L. -lcaesar -pthread -Wl,-rpath,.
	@echo "[OK] $(STAGE3_BIN) built."

$(STAGE4_BIN): secure_copy_stage4.cpp caesar.h $(LIB_NAME)
	$(CXX) $(CXXFLAGS) -o $@ $< -L. -lcaesar -pthread -Wl,-rpath,.
	@echo "[OK] $(STAGE4_BIN) built."

$(STAGE5_BIN): secure_copy_stage5.cpp caesar.h $(LIB_NAME)
	$(CXX) $(CXXFLAGS) -o $@ $< -L. -lcaesar -pthread -Wl,-rpath,.
	@echo "[OK] $(STAGE5_BIN) built."

.PHONY: install
install: $(LIB_NAME)
	cp $(LIB_NAME) $(INSTALL_DIR)/$(LIB_NAME)
	ldconfig
	@echo "[OK] Installed to $(INSTALL_DIR)."

.PHONY: test
test: all
	@if [ ! -f $(INPUT_FILE) ]; then \
		echo "Hello, World! This is a test file for the libcaesar library." > $(INPUT_FILE); \
		echo "XOR encryption works with any binary data, not just text." >> $(INPUT_FILE); \
		echo "Applying caesar twice with the same key restores the original data." >> $(INPUT_FILE); \
		echo "The quick brown fox jumps over the lazy dog." >> $(INPUT_FILE); \
	fi
	./$(TEST_BIN) ./$(LIB_NAME) $(TEST_KEY) $(INPUT_FILE) $(ENCRYPTED_FILE)
	./$(TEST_BIN) ./$(LIB_NAME) $(TEST_KEY) $(ENCRYPTED_FILE) $(DECRYPTED_FILE)
	@if diff -q $(INPUT_FILE) $(DECRYPTED_FILE) > /dev/null 2>&1; then \
		echo "[PASS] Files match - XOR is symmetric!"; \
	else \
		echo "[FAIL] Files differ!"; exit 1; \
	fi

.PHONY: test2
test2: all
	dd if=/dev/urandom of=big_input.bin bs=1024 count=1024 2>/dev/null
	./$(COPY_BIN) big_input.bin big_encrypted.bin $(TEST_KEY)
	./$(COPY_BIN) big_encrypted.bin big_decrypted.bin $(TEST_KEY)
	@if diff -q big_input.bin big_decrypted.bin > /dev/null 2>&1; then \
		echo "[PASS] Files match!"; \
	else \
		echo "[FAIL] Files differ!"; exit 1; \
	fi

.PHONY: test3
test3: $(COPY_BIN)
	@for i in 1 2 3 4 5; do echo "Test file $$i" > test_f$$i.txt; done
	./$(COPY_BIN) test_f1.txt test_f2.txt test_f3.txt test_f4.txt test_f5.txt out3/ $(TEST_KEY)
	./$(COPY_BIN) out3/test_f1.txt out3/test_f2.txt out3/test_f3.txt out3/test_f4.txt out3/test_f5.txt restored3/ $(TEST_KEY)
	@for i in 1 2 3 4 5; do \
		if diff -q test_f$$i.txt restored3/test_f$$i.txt > /dev/null 2>&1; then \
			echo "[PASS] test_f$$i.txt"; \
		else \
			echo "[FAIL] test_f$$i.txt"; exit 1; \
		fi; \
	done
	@cat log.txt

.PHONY: test4
test4: $(COPY_BIN)
	@for i in $(shell seq 1 10); do dd if=/dev/urandom of=t4_f$$i.bin bs=1024 count=512 2>/dev/null; done
	@echo "Auto mode (10 files, should pick parallel)"
	./$(COPY_BIN) t4_f1.bin t4_f2.bin t4_f3.bin t4_f4.bin t4_f5.bin t4_f6.bin t4_f7.bin t4_f8.bin t4_f9.bin t4_f10.bin out4/ $(TEST_KEY)
	@echo ""
	@echo "Sequential mode"
	./$(COPY_BIN) --mode=sequential t4_f1.bin t4_f2.bin t4_f3.bin t4_f4.bin t4_f5.bin out4_seq/ $(TEST_KEY)
	@echo ""
	@echo "Parallel mode"
	./$(COPY_BIN) --mode=parallel t4_f1.bin t4_f2.bin t4_f3.bin t4_f4.bin t4_f5.bin out4_par/ $(TEST_KEY)
	@rm -f t4_f*.bin
	@rm -rf out4/ out4_seq/ out4_par/

.PHONY: clean
clean:
	rm -f $(LIB_OBJ) $(LIB_NAME) $(TEST_BIN) $(COPY_BIN) \
	      $(STAGE1_BIN) $(STAGE2_BIN) $(STAGE3_BIN) \
	      $(STAGE4_BIN) $(STAGE5_BIN) \
	      $(ENCRYPTED_FILE) $(DECRYPTED_FILE) \
	      big_input.bin big_encrypted.bin big_decrypted.bin \
	      test_f*.txt log.txt t4_f*.bin
	@rm -rf out3/ restored3/ out4/ out4_seq/ out4_par/
	@echo "[OK] Cleaned."