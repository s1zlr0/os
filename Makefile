CXX      := g++
CXXFLAGS := -Wall -Wextra -pedantic -std=c++17 -fPIC

LIB_SRC  := caesar.cpp
LIB_OBJ  := caesar.o
LIB_NAME := libcaesar.so

TEST_SRC := os_pr1.cpp
TEST_BIN := os_pr1

COPY_SRC     := secure_copy.cpp
COPY_BIN     := secure_copy
WORKERS_COUNT := 4

INPUT_FILE     := input.txt
ENCRYPTED_FILE := encrypted.bin
DECRYPTED_FILE := decrypted.txt
TEST_KEY       := testkey

.PHONY: all
all: $(LIB_NAME) $(TEST_BIN) $(COPY_BIN)

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

.PHONY: clean
clean:
	rm -f $(LIB_OBJ) $(LIB_NAME) $(TEST_BIN) $(COPY_BIN) \
	      $(ENCRYPTED_FILE) $(DECRYPTED_FILE) \
	      big_input.bin big_encrypted.bin big_decrypted.bin \
	      test_f*.txt log.txt t4_f*.bin \
	      test5_segv test5_segv.cpp
	@rm -rf out3/ restored3/ out4/ out4_seq/ out4_par/ out5/ out5_dec/
	@echo "[OK] Cleaned."

.PHONY: test
test: all
	@if [ ! -f $(INPUT_FILE) ]; then \
		echo "Test data for caesar library." > $(INPUT_FILE); \
	fi
	./$(TEST_BIN) ./$(LIB_NAME) $(TEST_KEY) $(INPUT_FILE) $(ENCRYPTED_FILE)
	./$(TEST_BIN) ./$(LIB_NAME) $(TEST_KEY) $(ENCRYPTED_FILE) $(DECRYPTED_FILE)
	@if diff -q $(INPUT_FILE) $(DECRYPTED_FILE) > /dev/null 2>&1; then \
		echo "[PASS] Files match - RC4 is symmetric!"; \
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

.PHONY: test5
test5: $(LIB_NAME) $(TEST_BIN) $(COPY_BIN) test5_segv
	@echo "=== Task 5: Memory Protection Tests ==="
	@echo ""
	@echo "--- [1/4] Encrypt/decrypt with mmap-protected key ---"
	@if [ ! -f $(INPUT_FILE) ]; then \
		echo "Test data for task 5." > $(INPUT_FILE); \
	fi
	./$(TEST_BIN) ./$(LIB_NAME) $(TEST_KEY) $(INPUT_FILE) $(ENCRYPTED_FILE)
	./$(TEST_BIN) ./$(LIB_NAME) $(TEST_KEY) $(ENCRYPTED_FILE) $(DECRYPTED_FILE)
	@if diff -q $(INPUT_FILE) $(DECRYPTED_FILE) > /dev/null 2>&1; then \
		echo "[PASS] Encrypt/decrypt OK"; \
	else \
		echo "[FAIL] Files differ!"; exit 1; \
	fi
	@echo ""
	@echo "--- [2/4] secure_copy with protected key (sequential) ---"
	@echo "file_a" > t5_a.txt && echo "file_b" > t5_b.txt && echo "file_c" > t5_c.txt
	./$(COPY_BIN) --mode=sequential t5_a.txt t5_b.txt t5_c.txt out5/ $(TEST_KEY)
	./$(COPY_BIN) --mode=sequential out5/t5_a.txt out5/t5_b.txt out5/t5_c.txt out5_dec/ $(TEST_KEY)
	@for f in t5_a.txt t5_b.txt t5_c.txt; do \
		if diff -q $$f out5_dec/$$f > /dev/null 2>&1; then \
			echo "[PASS] $$f"; \
		else \
			echo "[FAIL] $$f"; exit 1; \
		fi; \
	done
	@echo ""
	@echo "--- [3/4] SIGSEGV on write to protected key memory ---"
	./test5_segv; \
	CODE=$$?; \
	if [ $$CODE -eq 1 ]; then \
		echo "[PASS] Exited with code 1"; \
	else \
		echo "[FAIL] Expected exit 1, got $$CODE"; exit 1; \
	fi
	@echo ""
	@echo "--- [4/4] key not exported from .so (cannot modify directly) ---"
	@if nm -D $(LIB_NAME) | grep -q "g_key_mem"; then \
		echo "[FAIL] g_key_mem is exported!"; exit 1; \
	else \
		echo "[PASS] g_key_mem is not exported — key cannot be modified directly"; \
	fi
	@echo ""
	@echo "=== [OK] All Task 5 tests passed ==="
	@rm -f t5_a.txt t5_b.txt t5_c.txt
	@rm -rf out5/ out5_dec/

test5_segv: test5_segv.cpp caesar.cpp caesar.h
	$(CXX) $(CXXFLAGS) -DTEST5_EXPOSE_KEY_ADDR -o $@ test5_segv.cpp caesar.cpp -ldl
	@echo "[OK] test5_segv built."

test5_segv.cpp:
	@printf '#include "caesar.h"\n#include <cstdio>\nint main(){\n    unsigned char master[]="testkey";\n    unsigned char salt[16]={};\n    set_key(master,7,salt);\n    char* p=(char*)get_key_mem_addr();\n    printf("Attempting write to protected key memory at %%p...\\n",(void*)p); fflush(stdout);\n    *p=1;\n    printf("ERROR: should not reach here\\n"); return 0;\n}\n' > $@

.PHONY: test6
test6: $(COPY_BIN)
	@echo "=== Task 6: Container Tests ==="
	@echo ""
	@echo "--- [1/5] Add single file ---"
	@rm -f t6.container
	@echo "Secret content file 1" > t6_f1.txt
	./$(COPY_BIN) --add t6.container t6_f1.txt mysecretkey
	@echo ""
	@echo "--- [2/5] Add directory recursively ---"
	@mkdir -p t6_dir/subdir
	@echo "File in root of dir" > t6_dir/root.txt
	@echo "File in subdir" > t6_dir/subdir/deep.txt
	./$(COPY_BIN) --add t6.container t6_dir mysecretkey
	@echo ""
	@echo "--- [3/5] List container (sorted by name) ---"
	./$(COPY_BIN) --list t6.container
	@COUNT=$$(./$(COPY_BIN) --list t6.container 2>&1 | grep "Files" | grep -o '[0-9]*'); \
	if [ "$$COUNT" -eq 3 ]; then \
		echo "[PASS] File count: $$COUNT"; \
	else \
		echo "[FAIL] Expected 3, got $$COUNT"; exit 1; \
	fi
	@echo ""
	@echo "--- [4/5] Extract and verify ---"
	./$(COPY_BIN) --extract t6.container t6_f1.txt /tmp/t6_out1.txt mysecretkey
	@diff t6_f1.txt /tmp/t6_out1.txt && echo "[PASS] t6_f1.txt extracted correctly"
	./$(COPY_BIN) --extract t6.container t6_dir/subdir/deep.txt /tmp/t6_deep.txt mysecretkey
	@diff t6_dir/subdir/deep.txt /tmp/t6_deep.txt && echo "[PASS] subdir/deep.txt extracted correctly"
	@echo ""
	@echo "--- [5/5] Wrong key gives different data ---"
	./$(COPY_BIN) --extract t6.container t6_f1.txt /tmp/t6_wrong.txt wrongkey
	@diff t6_f1.txt /tmp/t6_wrong.txt > /dev/null 2>&1 && echo "[FAIL] Wrong key gave same data" || echo "[PASS] Wrong key gives different data"
	@echo ""
	@echo "=== [OK] All Task 6 tests passed ==="
	@rm -f t6_f1.txt t6.container /tmp/t6_out1.txt /tmp/t6_deep.txt /tmp/t6_wrong.txt
	@rm -rf t6_dir/