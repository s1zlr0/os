#ifndef CAESAR_H
#define CAESAR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Инициализирует RC4-состояние из мастер-ключа и соли.
 * Состояние (256 байт) хранится в защищённой mmap-памяти.
 *
 * @param master     Мастер-ключ (строка)
 * @param master_len Длина мастер-ключа
 * @param salt       Соль (16 байт)
 */
void set_key(const unsigned char* master, int master_len,
             const unsigned char* salt);

/**
 * @brief Шифрует/дешифрует данные RC4 с текущим состоянием.
 * RC4 симметричен: применив дважды с одним состоянием → оригинал.
 *
 * @param src  Входной буфер
 * @param dst  Выходной буфер
 * @param len  Количество байт
 */
void cipher(void* src, void* dst, int len);

#ifdef TEST5_EXPOSE_KEY_ADDR
void* get_key_mem_addr(void);
#endif

#ifdef __cplusplus
}
#endif

#endif