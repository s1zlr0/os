/**
 * caesar.cpp — RC4 поточный шифр с защищённым состоянием.
 * - Ключ = master_key + salt, соль уникальна для каждого файла
 */

#include "caesar.h"
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <iostream>
#include <sys/mman.h>
#include <unistd.h>

// Размер защищённой области: S-box 256 байт + счётчики i, j
static const size_t RC4_STATE_SIZE = 258;

// Внутренняя структура — скрыта от пользователя
struct RC4State {
    unsigned char* mem; // указатель на mmap-память (RC4_STATE_SIZE байт)
};

// Удобный доступ к полям состояния (ссылки на начальный, 256 и 257 байты)
static inline unsigned char* rc4_s(RC4State* st) { return st->mem; }
static inline unsigned char& rc4_i(RC4State* st) { return st->mem[256]; }
static inline unsigned char& rc4_j(RC4State* st) { return st->mem[257]; }

// ── Обработчик сигнала

static void sigsegv_handler(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)ctx; //явное использование параметров, чтобы заглушить предупреждение компилятора
    void* fault_addr = info ? info->si_addr : nullptr;
    if (fault_addr != nullptr) {
        const char msg[] = "[SECURITY ERROR] Попытка записи в защищённую область памяти!\n";
        write(2, msg, sizeof(msg) - 1); //прямой системный вызов записи в файловый дескриптор 2
        _exit(EXIT_FAILURE);
    }
    struct sigaction sa_dfl;
    memset(&sa_dfl, 0, sizeof(sa_dfl));
    sa_dfl.sa_handler = SIG_DFL;
    sigaction(SIGSEGV, &sa_dfl, nullptr);
    raise(SIGSEGV);
}

static void install_sigsegv_handler() {
    static bool installed = false; // Это защита от двойной установки — если rc4_alloc вызвать несколько раз, обработчик установится только один раз.
    if (installed) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));// заполнение 0
    sa.sa_sigaction = sigsegv_handler; 
    sa.sa_flags = SA_SIGINFO; // флаг для передачи расширенной инфр
    sigaction(SIGSEGV, &sa, nullptr); // регистрация обработчика (номер сигнала, новый обработчик, куда сохр старый)
    installed = true;
}

// ── rc4_alloc / rc4_free

extern "C" RC4State* rc4_alloc(void) {
    install_sigsegv_handler();

    void* ptr = mmap(nullptr, RC4_STATE_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // выделение памяти
    if (ptr == MAP_FAILED) {
        std::cerr << "[ERROR] mmap failed\n";
        return nullptr;
    }
    memset(ptr, 0, RC4_STATE_SIZE); // заполнение 0
    mprotect(ptr, RC4_STATE_SIZE, PROT_READ); //только для чтения

    RC4State* state = new RC4State;
    state->mem = static_cast<unsigned char*>(ptr);
    return state;
}

extern "C" void rc4_free(RC4State* state) {
    if (!state) return;
    mprotect(state->mem, RC4_STATE_SIZE, PROT_READ | PROT_WRITE);
    memset(state->mem, 0, RC4_STATE_SIZE);
    mprotect(state->mem, RC4_STATE_SIZE, PROT_READ);
    munmap(state->mem, RC4_STATE_SIZE);
    delete state;
}

// ── RC4 KSA

static void rc4_ksa(RC4State* state, const unsigned char* key, int key_len) {
    mprotect(state->mem, RC4_STATE_SIZE, PROT_READ | PROT_WRITE);

    unsigned char* S = rc4_s(state);
    for (int k = 0; k < 256; ++k) S[k] = (unsigned char)k;

    unsigned char j = 0;
    for (int k = 0; k < 256; ++k) {
        j = j + S[k] + key[k % key_len];
        unsigned char tmp = S[k]; S[k] = S[j]; S[j] = tmp; // Перемешивание S-box по ключу. j — второй индекс, накапливается. key[k % key_len] — берём байты ключа циклически (если ключ короче 256 байт — повторяем). Каждую итерацию меняем местами S[k] и S[j]. После 256 итераций S-box перемешан уникальным образом зависящим от ключа.
    }
    rc4_i(state) = 0;
    rc4_j(state) = 0;

    mprotect(state->mem, RC4_STATE_SIZE, PROT_READ);
}

// ── Публичный интерфейс

extern "C" void rc4_init(RC4State* state,
                         const unsigned char* master, int master_len,
                         const unsigned char* salt) {
    if (!state) return;

    // Составляем ключ: master || salt
    unsigned char combined[256]; //временный буфер на стеке для объединённого ключа.
    int salt_len = 16;

    int copy_master = master_len < 256 ? master_len : 256;
    memcpy(combined, master, copy_master);// Копируем мастер-ключ
    int room = 256 - copy_master;
    int copy_salt = salt_len < room ? salt_len : room;
    memcpy(combined + copy_master, salt, copy_salt);//копируем соль
    int total = copy_master + copy_salt;

    rc4_ksa(state, combined, total);
    memset(combined, 0, sizeof(combined));
}
// генерируем гамму
extern "C" void rc4_cipher(RC4State* state, void* src, void* dst, int len) {
    if (!state || !src || !dst || len <= 0) return;

    const unsigned char* in  = static_cast<const unsigned char*>(src);
    unsigned char*       out = static_cast<unsigned char*>(dst);

    mprotect(state->mem, RC4_STATE_SIZE, PROT_READ | PROT_WRITE);

    unsigned char* S = rc4_s(state);
    unsigned char  i = rc4_i(state);
    unsigned char  j = rc4_j(state);

    for (int k = 0; k < len; ++k) {
        ++i;
        j += S[i];
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        unsigned char keystream = S[(unsigned char)(S[i] + S[j])];
        out[k] = in[k] ^ keystream;
    }

    rc4_i(state) = i;
    rc4_j(state) = j;

    mprotect(state->mem, RC4_STATE_SIZE, PROT_READ);
}

#ifdef TEST5_EXPOSE_KEY_ADDR
extern "C" void* get_key_mem_addr(RC4State* state) {
    return state ? state->mem : nullptr;
}
#endif