#ifndef CAESAR_H
#define CAESAR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Устанавливает ключ шифрования XOR.
 * Ключ сохраняется внутри библиотеки в статической переменной.
 *
 * @param key Символ-ключ для операции XOR
 */
void set_key(char key);

/**
 * @brief Шифрует/дешифрует данные побайтовым XOR с установленным ключом.
 * Поскольку XOR симметрична: caesar(caesar(data)) == data.
 * Поддерживает in-place шифрование (src == dst).
 *
 * @param src   Указатель на входной буфер (исходные данные)
 * @param dst   Указатель на выходной буфер (результат)
 * @param len   Количество байт для обработки
 */
void caesar(void* src, void* dst, int len);

#ifdef __cplusplus
}
#endif

#endif
