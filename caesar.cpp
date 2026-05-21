/**
 * caesar.cpp — RC4 поточный шифр с защищённым состоянием.
 *
 * Task 5: состояние RC4 (256 байт) хранится в защищённой mmap-памяти.
 * Task 6: ключ = мастер-ключ || соль, для каждого файла своя соль.
 */

#include "caesar.h"
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <iostream>
#include <sys/mman.h>
#include <unistd.h>

// RC4-состояние: 256 байт S-box + 2 байта счётчиков i, j
static const size_t RC4_STATE_SIZE = 256 + 2;

// Указатель на защищённую область памяти для RC4-состояния
static unsigned char* g_key_mem = nullptr;

// Удобный доступ к частям состояния
static inline unsigned char* rc4_s()  { return g_key_mem; }        // S-box [0..255]
static inline unsigned char& rc4_i()  { return g_key_mem[256]; }   // счётчик i
static inline unsigned char& rc4_j()  { return g_key_mem[257]; }   // счётчик j

// ── Обработчик SIGSEGV ──────────────────────────────────────────────────────

static void sigsegv_handler(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)ctx;
    void* fault_addr = info ? info->si_addr : nullptr;
    if (g_key_mem != nullptr
        && fault_addr >= static_cast<void*>(g_key_mem)
        && fault_addr <  static_cast<void*>(g_key_mem + RC4_STATE_SIZE))
    {
        const char msg[] = "[SECURITY ERROR] Попытка записи в защищённую область памяти!\n";
        write(2, msg, sizeof(msg) - 1);
        _exit(EXIT_FAILURE);
    }
    struct sigaction sa_dfl;
    memset(&sa_dfl, 0, sizeof(sa_dfl));
    sa_dfl.sa_handler = SIG_DFL;
    sigaction(SIGSEGV, &sa_dfl, nullptr);
    raise(SIGSEGV);
}

// ── Управление защищённой памятью ───────────────────────────────────────────

static void key_mem_init() {
    if (g_key_mem != nullptr) return;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);

    void* ptr = mmap(nullptr, RC4_STATE_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        std::cerr << "[ERROR] mmap failed\n";
        exit(EXIT_FAILURE);
    }
    g_key_mem = static_cast<unsigned char*>(ptr);
    memset(g_key_mem, 0, RC4_STATE_SIZE);

    if (mprotect(g_key_mem, RC4_STATE_SIZE, PROT_READ) != 0) {
        std::cerr << "[ERROR] mprotect(PROT_READ) failed\n";
        munmap(g_key_mem, RC4_STATE_SIZE);
        exit(EXIT_FAILURE);
    }
}

static void key_mem_destroy() {
    if (g_key_mem == nullptr) return;
    mprotect(g_key_mem, RC4_STATE_SIZE, PROT_READ | PROT_WRITE);
    memset(g_key_mem, 0, RC4_STATE_SIZE);
    mprotect(g_key_mem, RC4_STATE_SIZE, PROT_READ);
    munmap(g_key_mem, RC4_STATE_SIZE);
    g_key_mem = nullptr;
}

static struct KeyMemGuard {
    KeyMemGuard()  { key_mem_init(); }
    ~KeyMemGuard() { key_mem_destroy(); }
} g_key_guard;

// ── RC4 KSA (Key Scheduling Algorithm) ─────────────────────────────────────
// Инициализирует S-box по ключу = master || salt

static void rc4_ksa(const unsigned char* key, int key_len) {
    // Открываем запись в защищённую память
    mprotect(g_key_mem, RC4_STATE_SIZE, PROT_READ | PROT_WRITE);

    unsigned char* S = rc4_s();
    // Инициализация S-box
    for (int k = 0; k < 256; ++k) S[k] = (unsigned char)k;

    // Перемешивание по ключу
    unsigned char j = 0;
    for (int k = 0; k < 256; ++k) {
        j = j + S[k] + key[k % key_len];
        unsigned char tmp = S[k]; S[k] = S[j]; S[j] = tmp;
    }
    // Сбрасываем счётчики PRGA
    rc4_i() = 0;
    rc4_j() = 0;

    // Закрываем запись
    mprotect(g_key_mem, RC4_STATE_SIZE, PROT_READ);
}

// ── Публичный интерфейс ─────────────────────────────────────────────────────

// Инициализирует RC4-состояние: ключ = master || salt (всего до 256 байт)
extern "C" void set_key(const unsigned char* master, int master_len,
                        const unsigned char* salt) {
    // Составляем объединённый ключ: master || salt
    unsigned char combined[256];
    int salt_len = 16;
    int total = master_len + salt_len;
    if (total > 256) total = 256;

    memcpy(combined, master, master_len < 256 ? master_len : 256);
    if (master_len < 256)
        memcpy(combined + master_len, salt,
               (salt_len < 256 - master_len) ? salt_len : 256 - master_len);

    rc4_ksa(combined, total);
    // Затираем временный буфер
    memset(combined, 0, sizeof(combined));
}

// Шифрует/дешифрует данные RC4 PRGA
extern "C" void cipher(void* src, void* dst, int len) {
    if (!src || !dst || len <= 0) return;

    const unsigned char* in  = static_cast<const unsigned char*>(src);
    unsigned char*       out = static_cast<unsigned char*>(dst);

    // Открываем запись для изменения состояния RC4
    mprotect(g_key_mem, RC4_STATE_SIZE, PROT_READ | PROT_WRITE);

    unsigned char* S = rc4_s();
    unsigned char  i = rc4_i();
    unsigned char  j = rc4_j();

    for (int k = 0; k < len; ++k) {
        ++i;
        j += S[i];
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        unsigned char keystream = S[(unsigned char)(S[i] + S[j])];
        out[k] = in[k] ^ keystream;
    }

    // Сохраняем обновлённые счётчики
    rc4_i() = i;
    rc4_j() = j;

    // Закрываем запись
    mprotect(g_key_mem, RC4_STATE_SIZE, PROT_READ);
}

#ifdef TEST5_EXPOSE_KEY_ADDR
void* get_key_mem_addr(void) { return g_key_mem; }
#endif