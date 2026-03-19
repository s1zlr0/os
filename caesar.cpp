/**
 * caesar.cpp — реализация простой криптографической библиотеки
 *
 * Алгоритм: побайтовый XOR с ключом.
 * XOR симметричен: применив caesar дважды с тем же ключом, получим исходные данные.
 */

#include "caesar.h"
#include <cstring>

// Статическая переменная для хранения ключа внутри библиотеки.
// Инициализируется нулём по умолчанию.
static char g_key = 0;

//Устанавливает ключ шифрования.

extern "C" void set_key(char key) {
    g_key = key;
}


extern "C" void caesar(void* src, void* dst, int len) {
    if (!src || !dst || len <= 0) {
        return; 
    }

    const unsigned char* in  = static_cast<const unsigned char*>(src);
    unsigned char*       out = static_cast<unsigned char*>(dst);
    unsigned char        key = static_cast<unsigned char>(g_key);

    for (int i = 0; i < len; ++i) {
        out[i] = in[i] ^ key;
    }
}