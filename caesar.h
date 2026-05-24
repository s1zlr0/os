#ifndef CAESAR_H
#define CAESAR_H

#ifdef __cplusplus
extern "C" {
#endif

// RC4-состояние для одного файла — непрозрачный тип
// Память выделяется через mmap, защищается mprotect
typedef struct RC4State RC4State;

// Выделяет защищённую память под состояние RC4
RC4State* rc4_alloc(void);

// Затирает нулями и освобождает защищённую память
void rc4_free(RC4State* state);

// Инициализирует RC4 ключом = master || salt
void rc4_init(RC4State* state,
              const unsigned char* master, int master_len,
              const unsigned char* salt);

// Шифрует/дешифрует данные (RC4 симметричен)
void rc4_cipher(RC4State* state, void* src, void* dst, int len);

#ifdef TEST5_EXPOSE_KEY_ADDR
void* get_key_mem_addr(RC4State* state);
#endif

#ifdef __cplusplus
}
#endif

#endif