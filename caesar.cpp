/**
 * caesar.cpp — реализация простой криптографической библиотеки
 *
 * Алгоритм: побайтовый XOR с ключом.
 * XOR симметричен: применив caesar дважды с тем же ключом, получим исходные данные.
 *
 * Task 5: ключ хранится в защищённой области памяти (mmap + mprotect).
 */

#include "caesar.h"
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <iostream>
#include <sys/mman.h>

static const size_t KEY_MEM_SIZE = 16;

// Указатель на защищённую область памяти для ключа
static unsigned char* g_key_mem = nullptr;

// Обработчик SIGSEGV: различает попытку записи в защищённую область ключа
// и обычные ошибки доступа (nullptr, освобождённая память и т.п.)
static void sigsegv_handler(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)ctx;
    void* fault_addr = info ? info->si_addr : nullptr;
    // Проверяем: адрес попадает в защищённую область ключа?
    if (g_key_mem != nullptr
        && fault_addr >= static_cast<void*>(g_key_mem)
        && fault_addr <  static_cast<void*>(g_key_mem + KEY_MEM_SIZE))
    {
        const char msg[] = "[SECURITY ERROR] Попытка записи в защищённую область памяти!\n";
        write(2, msg, sizeof(msg) - 1);
        _exit(EXIT_FAILURE);
    }
    // Обычный SIGSEGV (nullptr, freed memory и т.п.) — восстанавливаем
    // стандартное поведение и повторно генерируем сигнал
    struct sigaction sa_dfl;
    memset(&sa_dfl, 0, sizeof(sa_dfl));
    sa_dfl.sa_handler = SIG_DFL;
    sigaction(SIGSEGV, &sa_dfl, nullptr);
    raise(SIGSEGV);
}

// Инициализирует защищённую память и устанавливает обработчик SIGSEGV
static void key_mem_init() {
    if (g_key_mem != nullptr) return;

    // Устанавливаем обработчик SIGSEGV с SA_SIGINFO для получения адреса
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);

    // 1. Выделяем память (mprotect #1: PROT_READ | PROT_WRITE)
    void* ptr = mmap(nullptr, KEY_MEM_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        std::cerr << "[ERROR] mmap failed\n";
        exit(EXIT_FAILURE);
    }
    g_key_mem = static_cast<unsigned char*>(ptr);

    // Инициализируем нулём
    memset(g_key_mem, 0, KEY_MEM_SIZE);

    // 2. Устанавливаем права только на чтение (mprotect #2: PROT_READ)
    if (mprotect(g_key_mem, KEY_MEM_SIZE, PROT_READ) != 0) {
        std::cerr << "[ERROR] mprotect(PROT_READ) failed\n";
        munmap(g_key_mem, KEY_MEM_SIZE);
        exit(EXIT_FAILURE);
    }
}

// Освобождает защищённую память с затиранием ключа
static void key_mem_destroy() {
    if (g_key_mem == nullptr) return;

    // Открываем запись для затирания
    mprotect(g_key_mem, KEY_MEM_SIZE, PROT_READ | PROT_WRITE);
    memset(g_key_mem, 0, KEY_MEM_SIZE);
    // Возвращаем защиту перед munmap
    mprotect(g_key_mem, KEY_MEM_SIZE, PROT_READ);
    munmap(g_key_mem, KEY_MEM_SIZE);
    g_key_mem = nullptr;
}

// Автоматическая очистка при завершении программы
static struct KeyMemGuard {
    KeyMemGuard()  { key_mem_init(); }
    ~KeyMemGuard() { key_mem_destroy(); }
} g_key_guard;

// Устанавливает ключ шифрования в защищённой памяти
extern "C" void set_key(char key) {
    // 3. Открываем запись (mprotect #3: PROT_READ | PROT_WRITE)
    if (mprotect(g_key_mem, KEY_MEM_SIZE, PROT_READ | PROT_WRITE) != 0) {
        std::cerr << "[ERROR] mprotect(PROT_READ|PROT_WRITE) failed\n";
        exit(EXIT_FAILURE);
    }
    memcpy(g_key_mem, &key, 1);
    // Возвращаем защиту только на чтение
    if (mprotect(g_key_mem, KEY_MEM_SIZE, PROT_READ) != 0) {
        std::cerr << "[ERROR] mprotect(PROT_READ) failed\n";
        exit(EXIT_FAILURE);
    }
}

extern "C" void caesar(void* src, void* dst, int len) {
    if (!src || !dst || len <= 0) {
        return;
    }

    const unsigned char* in  = static_cast<const unsigned char*>(src);
    unsigned char*       out = static_cast<unsigned char*>(dst);

    // Временно расширяем права, используем ключ напрямую из защищённой памяти,
    // сразу возвращаем защиту
    mprotect(g_key_mem, KEY_MEM_SIZE, PROT_READ | PROT_WRITE);
    for (int i = 0; i < len; ++i) {
        out[i] = in[i] ^ g_key_mem[0];
    }
    mprotect(g_key_mem, KEY_MEM_SIZE, PROT_READ);
}

#ifdef TEST5_EXPOSE_KEY_ADDR
void* get_key_mem_addr(void) { return g_key_mem; }
#endif