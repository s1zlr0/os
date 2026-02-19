/**
 * os_pr1.cpp — тестовая консольная программа для демонстрации caesar.dll / libcaesar.so.
 *
 * Запуск:
 *   os_pr1.exe <путь_к_dll> <ключ> <входной_файл> <выходной_файл>
 *
 * Пример:
 *   os_pr1.exe caesar.dll 42 input.txt encrypted.bin
 *   os_pr1.exe caesar.dll 42 encrypted.bin decrypted.txt
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cctype>

// ── Платформо-зависимый загрузчик DLL/SO --------------------------------────
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>

    using LibHandle = HMODULE;

    static LibHandle lib_open(const char* path) {
        return LoadLibraryA(path);
    }
    static void* lib_sym(LibHandle h, const char* name) {
        return reinterpret_cast<void*>(GetProcAddress(h, name));
    }
    static void lib_close(LibHandle h) {
        FreeLibrary(h);
    }
    static std::string lib_error() {
        DWORD code = GetLastError();
        char buf[256];
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       nullptr, code, 0, buf, sizeof(buf), nullptr);
        return std::string(buf);
    }
#else
    #include <dlfcn.h>

    using LibHandle = void*;

    static LibHandle lib_open(const char* path) {
        return dlopen(path, RTLD_LAZY);
    }
    static void* lib_sym(LibHandle h, const char* name) {
        return dlsym(h, name);
    }
    static void lib_close(LibHandle h) {
        dlclose(h);
    }
    static std::string lib_error() {
        const char* e = dlerror();
        return e ? std::string(e) : "unknown error";
    }
#endif
// ----------------------------------------------------------------────────────

// Типы указателей на функции библиотеки
typedef void (*set_key_fn)(char);
typedef void (*caesar_fn)(void*, void*, int);

// Читает файл целиком в вектор байт
static bool read_file(const std::string& path, std::vector<unsigned char>& data) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Не удалось открыть входной файл: " << path << "\n";
        return false;
    }
    data.assign(std::istreambuf_iterator<char>(file),
                std::istreambuf_iterator<char>());
    return true;
}

// Записывает вектор байт в файл
static bool write_file(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Не удалось открыть выходной файл: " << path << "\n";
        return false;
    }
    file.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
    return file.good();
}

// Выводит содержимое буфера в консоль:
//   - печатаемые символы — как есть
//   - непечатаемые и нулевые байты — в виде \xNN
// Бинарные файлы показываются в виде HEX-дампа с ASCII-колонкой.
static void print_content(const std::string& label,
                          const std::vector<unsigned char>& data,
                          bool is_binary)
{
    const size_t PREVIEW = 256; // максимум байт для предпросмотра
    std::cout << "\n" << label << " (" << data.size() << " байт):\n";

    if (!is_binary) {
        // Текстовый режим: просто печатаем строки
        size_t limit = std::min(data.size(), PREVIEW);
        for (size_t i = 0; i < limit; ++i) {
            unsigned char c = data[i];
            if (c == '\n')      std::cout << '\n';
            else if (c == '\r') { /* пропускаем \r */ }
            else if (c >= 0x20) std::cout << c;
            else                std::cout << "\\x" << std::hex
                                          << std::uppercase
                                          << static_cast<int>(c)
                                          << std::dec;
        }
        if (data.size() > PREVIEW)
            std::cout << "\n... (showed " << PREVIEW << " of " << data.size() << " bytes)";
        std::cout << "\n";
    } else {
        // Бинарный режим: HEX-дамп с ASCII-колонкой
        std::cout << "[HEX]\n";
        const int ROW = 16;
        size_t limit = std::min(data.size(), PREVIEW);
        for (size_t i = 0; i < limit; i += ROW) {
            // Адрес
            std::cout << "  " << std::hex << std::uppercase;
            std::cout.width(4); std::cout.fill('0');
            std::cout << i << std::dec << "  ";

            // HEX-байты
            for (int j = 0; j < ROW; ++j) {
                if (i + j < limit) {
                    std::cout << std::hex << std::uppercase;
                    std::cout.width(2); std::cout.fill('0');
                    std::cout << static_cast<int>(data[i + j]) << std::dec << ' ';
                } else {
                    std::cout << "   ";
                }
                if (j == 7) std::cout << ' ';
            }

            // ASCII-колонка
            std::cout << " |";
            for (int j = 0; j < ROW && i + j < limit; ++j) {
                unsigned char c = data[i + j];
                std::cout << (c >= 0x20 && c < 0x7F ? static_cast<char>(c) : '.');
            }
            std::cout << "|\n";
        }
        if (data.size() > PREVIEW)
            std::cout << "  ... (showed " << PREVIEW << " of " << data.size() << " bytes)\n";
    }
}

int main(int argc, char* argv[]) {
    // Проверка аргументов
    if (argc != 5) {
        std::cerr << "Использование:\n"
                  << "  " << argv[0] << " <dll/so> <ключ> <входной_файл> <выходной_файл>\n\n"
                  << "  <dll/so>         — путь к динамической библиотеке\n"
                  << "  <ключ>           — число 0-255 или одиночный ASCII-символ\n"
                  << "  <входной_файл>   — исходные данные\n"
                  << "  <выходной_файл>  — результат шифрования/дешифрования\n\n"
                  << "Примеры:\n"
                  << "  " << argv[0] << " caesar.dll 42 input.txt encrypted.bin\n"
                  << "  " << argv[0] << " caesar.dll 42 encrypted.bin decrypted.txt\n";
        return EXIT_FAILURE;
    }

    const std::string lib_path = argv[1];
    const std::string key_arg  = argv[2];
    const std::string in_path  = argv[3];
    const std::string out_path = argv[4];

    // Парсим ключ: одиночный не-цифровой символ → берём ASCII-код,
    // иначе парсим как целое число
    char key = 0;
    if (key_arg.size() == 1 && !std::isdigit(static_cast<unsigned char>(key_arg[0]))) {
        key = key_arg[0];
    } else {
        key = static_cast<char>(std::atoi(key_arg.c_str()) & 0xFF);
    }

    std::cout << "[INFO] Библиотека : " << lib_path << "\n"
              << "[INFO] Ключ       : " << static_cast<int>(static_cast<unsigned char>(key))
              << " (0x" << std::hex << static_cast<int>(static_cast<unsigned char>(key))
              << std::dec << ")\n"
              << "[INFO] Вход       : " << in_path  << "\n"
              << "[INFO] Выход      : " << out_path << "\n";

    // ── Динамическая загрузка библиотеки 
    LibHandle handle = lib_open(lib_path.c_str());
    if (!handle) {
        std::cerr << "[ERROR] Не удалось загрузить библиотеку: " << lib_error() << "\n";
        return EXIT_FAILURE;
    }
    std::cout << "[INFO] Библиотека загружена успешно.\n";

    set_key_fn fn_set_key = reinterpret_cast<set_key_fn>(lib_sym(handle, "set_key"));
    if (!fn_set_key) {
        std::cerr << "[ERROR] Не найдена функция set_key: " << lib_error() << "\n";
        lib_close(handle);
        return EXIT_FAILURE;
    }

    caesar_fn fn_caesar = reinterpret_cast<caesar_fn>(lib_sym(handle, "caesar"));
    if (!fn_caesar) {
        std::cerr << "[ERROR] Не найдена функция caesar: " << lib_error() << "\n";
        lib_close(handle);
        return EXIT_FAILURE;
    }

    // ── Чтение входного файла
    std::vector<unsigned char> data;
    if (!read_file(in_path, data)) {
        lib_close(handle);
        return EXIT_FAILURE;
    }
    std::cout << "[INFO] Прочитано байт: " << data.size() << "\n";

    // Определяем: файл текстовый или бинарный
    // Считаем файл текстовым, если в нём нет нулевых байт и
    // доля печатаемых символов > 90%
    auto detect_binary = [](const std::vector<unsigned char>& buf) -> bool {
        if (buf.empty()) return false;
        size_t check = std::min(buf.size(), size_t(512));
        size_t printable = 0;
        for (size_t i = 0; i < check; ++i) {
            unsigned char c = buf[i];
            if (c == 0) return true; // нулевой байт — точно бинарный
            if (c >= 0x20 || c == '\n' || c == '\r' || c == '\t') ++printable;
        }
        return (printable * 100 / check) < 90;
    };

    bool input_is_binary = detect_binary(data);

    // Показываем содержимое входного файла
    print_content("ВХОДНОЙ ФАЙЛ: " + in_path, data, input_is_binary);

    // ── Шифрование / дешифрование (in-place)
    fn_set_key(key);
    fn_caesar(data.data(), data.data(), static_cast<int>(data.size()));

    // Показываем содержимое выходного файла (всегда бинарно после шифрования,
    // но если ключ=0 или это дешифрование — может быть текстом)
    bool output_is_binary = detect_binary(data);
    print_content("ВЫХОДНОЙ ФАЙЛ: " + out_path, data, output_is_binary);

    // ── Запись выходного файла 
    if (!write_file(out_path, data)) {
        lib_close(handle);
        return EXIT_FAILURE;
    }
    std::cout << "[INFO] Результат записан в: " << out_path << "\n";
    std::cout << "[OK]   Операция завершена успешно.\n";

    lib_close(handle);
    return EXIT_SUCCESS;
}