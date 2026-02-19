
# Makefile для проекта libcaesar (XOR-шифрование)

# Компилятор и флаги
CXX      := g++
# -Wall -Wextra -pedantic — обязательные по заданию флаги предупреждений
# -fPIC                   — Position-Independent Code, требуется для .so
CXXFLAGS := -Wall -Wextra -pedantic -fPIC -std=c++17

# Имена файлов
LIB_SRC  := caesar.cpp
LIB_OBJ  := caesar.o
LIB_NAME := libcaesar.so

TEST_SRC := os_pr1.cpp
TEST_BIN := os_pr1

INSTALL_DIR := /usr/local/lib

# Тестовые файлы
INPUT_FILE     := input.txt
ENCRYPTED_FILE := encrypted.bin
DECRYPTED_FILE := decrypted.txt
# Ключ шифрования для тестового запуска (число 0–255)
TEST_KEY       := 42

# Цель по умолчанию: собрать библиотеку и тестовую программу

.PHONY: all
all: $(LIB_NAME) $(TEST_BIN)

# Сборка разделяемой библиотеки
$(LIB_NAME): $(LIB_OBJ)
	$(CXX) -shared -o $@ $^
	@echo "[OK] Библиотека $(LIB_NAME) собрана."

# Компиляция объектного файла библиотеки
$(LIB_OBJ): $(LIB_SRC) caesar.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Сборка тестовой программы (динамически линкует только dl)
$(TEST_BIN): $(TEST_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< -ldl
	@echo "[OK] Тестовая программа $(TEST_BIN) собрана."


# install: копирование библиотеки в системный каталог

.PHONY: install
install: $(LIB_NAME)
	@echo "[INFO] Копирование $(LIB_NAME) → $(INSTALL_DIR)/"
	cp $(LIB_NAME) $(INSTALL_DIR)/$(LIB_NAME)
	ldconfig
	@echo "[OK] Установка завершена. Кэш динамических библиотек обновлён."

# test: демонстрация шифрования и симметричного дешифрования

.PHONY: test
test: all
	@# Create input.txt only if it does NOT exist - never overwrite user file
	@if [ ! -f $(INPUT_FILE) ]; then \
		echo "Hello, World! This is a test file for the libcaesar library." > $(INPUT_FILE); \
		echo "[INFO] Created test file $(INPUT_FILE)."; \
	fi
	@echo ""
	@echo "TEST 1: encryption "
	./$(TEST_BIN) ./$(LIB_NAME) $(TEST_KEY) $(INPUT_FILE) $(ENCRYPTED_FILE)

	@echo ""
	@echo "TEST 2: decryption (same key) "
	./$(TEST_BIN) ./$(LIB_NAME) $(TEST_KEY) $(ENCRYPTED_FILE) $(DECRYPTED_FILE)

	@echo ""

	@echo ""

# clean: удаление артефактов сборки

.PHONY: clean
clean:
	rm -f $(LIB_OBJ) $(LIB_NAME) $(TEST_BIN) \
	      $(ENCRYPTED_FILE) $(DECRYPTED_FILE)
	@echo "[OK] Артефакты удалены."