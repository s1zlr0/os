CXX           := g++
CXXFLAGS      := -Wall -Wextra -pedantic -std=c++17 -fPIC
LIB_SRC       := caesar.cpp
LIB_OBJ       := caesar.o
LIB_NAME      := libcaesar.so
COPY_SRC      := secure_copy.cpp
COPY_BIN      := secure_copy
WORKERS_COUNT := 4

.PHONY: all
all: $(LIB_NAME) $(COPY_BIN)

$(LIB_NAME): $(LIB_OBJ)
	$(CXX) -shared -o $@ $^
	@echo "[OK] $(LIB_NAME) built."

$(LIB_OBJ): $(LIB_SRC) caesar.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(COPY_BIN): $(COPY_SRC) caesar.h $(LIB_NAME)
	$(CXX) $(CXXFLAGS) -DWORKERS_COUNT=$(WORKERS_COUNT) -o $@ $< -L. -lcaesar -pthread -Wl,-rpath,.
	@echo "[OK] $(COPY_BIN) built."

.PHONY: clean
clean:
	rm -f $(LIB_OBJ) $(LIB_NAME) $(COPY_BIN) \
	      test5_segv test5_segv.cpp \
	      t5_a.txt t5_b.txt t5_c.txt t5.img \
	      t6_f1.txt t6.img
	@rm -rf t6_dir/ /tmp/t5_*.txt /tmp/t6_*.txt
	@echo "[OK] Cleaned."

.PHONY: test5
test5: $(LIB_NAME) $(COPY_BIN) test5_segv
	@echo "Task 5: Memory Protection Tests"
	@echo ""
	@echo "[1/3] SIGSEGV on write to protected key memory"
	./test5_segv; \
	CODE=$$?; \
	if [ $$CODE -eq 1 ]; then \
		echo "[PASS] Exited with code 1"; \
	else \
		echo "[FAIL] Expected exit 1, got $$CODE"; exit 1; \
	fi
	@echo ""
	@echo "[2/3] RC4 state not globally exported from .so"
	@if nm -D $(LIB_NAME) | grep -qE "^[0-9a-f]+ [A-Z] g_key_mem"; then \
		echo "[FAIL] g_key_mem is exported!"; exit 1; \
	else \
		echo "[PASS] RC4 state not globally exported"; \
	fi
	@echo ""
	@echo "[3/3] Add/get with protected key"
	@echo "file_a" > t5_a.txt && echo "file_b" > t5_b.txt && echo "file_c" > t5_c.txt
	@rm -f t5.img
	./$(COPY_BIN) -add -key testkey -image t5.img t5_a.txt t5_b.txt t5_c.txt
	./$(COPY_BIN) -get -key testkey -image t5.img -out /tmp/t5_a_out.txt t5_a.txt
	./$(COPY_BIN) -get -key testkey -image t5.img -out /tmp/t5_b_out.txt t5_b.txt
	./$(COPY_BIN) -get -key testkey -image t5.img -out /tmp/t5_c_out.txt t5_c.txt
	@diff t5_a.txt /tmp/t5_a_out.txt > /dev/null 2>&1 && echo "[PASS] t5_a.txt" || { echo "[FAIL] t5_a.txt"; exit 1; }
	@diff t5_b.txt /tmp/t5_b_out.txt > /dev/null 2>&1 && echo "[PASS] t5_b.txt" || { echo "[FAIL] t5_b.txt"; exit 1; }
	@diff t5_c.txt /tmp/t5_c_out.txt > /dev/null 2>&1 && echo "[PASS] t5_c.txt" || { echo "[FAIL] t5_c.txt"; exit 1; }
	@echo ""
	@echo "[OK] All Task 5 tests passed"
	@rm -f t5_a.txt t5_b.txt t5_c.txt t5.img /tmp/t5_a_out.txt /tmp/t5_b_out.txt /tmp/t5_c_out.txt

test5_segv: test5_segv.cpp caesar.cpp caesar.h
	$(CXX) $(CXXFLAGS) -DTEST5_EXPOSE_KEY_ADDR -o $@ test5_segv.cpp caesar.cpp -ldl
	@echo "[OK] test5_segv built."

test5_segv.cpp:
	@printf '#include "caesar.h"\n#include <cstdio>\nint main(){\n    unsigned char master[]="testkey";\n    unsigned char salt[16]={};\n    RC4State* st=rc4_alloc();\n    rc4_init(st,master,7,salt);\n    char* p=(char*)get_key_mem_addr(st);\n    printf("Attempting write to protected key memory at %%p...\\n",(void*)p); fflush(stdout);\n    *p=1;\n    printf("ERROR: should not reach here\\n"); return 0;\n}\n' > $@

.PHONY: test6
test6: $(COPY_BIN)
	@echo "Task 6: Container Tests"
	@echo ""
	@echo "[1/5] Add single file"
	@rm -f t6.img
	@echo "Secret content file 1" > t6_f1.txt
	./$(COPY_BIN) -add -key testkey -image t6.img t6_f1.txt
	@echo ""
	@echo "[2/5] Add directory recursively (depth 4)"
	@mkdir -p t6_dir/sub1/sub2/sub3/sub4
	@echo "root file"  > t6_dir/root.txt
	@echo "deep file"  > t6_dir/sub1/sub2/sub3/sub4/deep.txt
	./$(COPY_BIN) -add -key testkey -image t6.img t6_dir
	@echo ""
	@echo "[3/5] List image (sorted by name)"
	./$(COPY_BIN) -list -image t6.img
	@COUNT=$$(./$(COPY_BIN) -list -image t6.img 2>&1 | grep "Files" | grep -o '[0-9]*'); \
	if [ "$$COUNT" -eq 3 ]; then \
		echo "[PASS] File count: $$COUNT"; \
	else \
		echo "[FAIL] Expected 3, got $$COUNT"; exit 1; \
	fi
	@echo ""
	@echo "[4/5] Extract and verify"
	./$(COPY_BIN) -get -key testkey -image t6.img -out /tmp/t6_out1.txt t6_f1.txt
	@diff t6_f1.txt /tmp/t6_out1.txt && echo "[PASS] t6_f1.txt"
	./$(COPY_BIN) -get -key testkey -image t6.img -out /tmp/t6_deep.txt t6_dir/sub1/sub2/sub3/sub4/deep.txt
	@diff t6_dir/sub1/sub2/sub3/sub4/deep.txt /tmp/t6_deep.txt && echo "[PASS] deep.txt (depth 4)"
	@echo ""
	@echo "[5/5] Wrong key gives different data"
	./$(COPY_BIN) -get -key wrongkey -image t6.img -out /tmp/t6_wrong.txt t6_f1.txt
	@diff t6_f1.txt /tmp/t6_wrong.txt > /dev/null 2>&1 && echo "[FAIL] Wrong key gave same data" || echo "[PASS] Wrong key gives different data"
	@echo ""
	@echo "[OK] All Task 6 tests passed"
	@rm -f t6_f1.txt t6.img /tmp/t6_out1.txt /tmp/t6_deep.txt /tmp/t6_wrong.txt
	@rm -rf t6_dir/