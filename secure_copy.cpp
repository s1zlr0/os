/**
 * secure_copy.cpp — защищённый контейнер файлов.
 *
 * Формат блока в контейнере:
 *   [4 байта] размер данных файла
 *   [4 байта] длина имени файла
 *   [16 байт] соль
 *   [N байт]  имя файла (без нуля)
 *   [M байт]  зашифрованные данные файла
 */

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>

#include "caesar.h"

// Task 6: контейнер файлов с RC4-шифрованием


static const int SALT_SIZE = 16;
static const int MAX_CONTAINER_THREADS = 5;

// Генерирует случайную соль из /dev/urandom
static void gen_salt(unsigned char* salt) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, salt, SALT_SIZE) != SALT_SIZE) {
        // fallback: псевдослучайная соль
        for (int i = 0; i < SALT_SIZE; ++i)
            salt[i] = (unsigned char)(rand() ^ (i * 37) ^ (int)time(nullptr));
    }
    if (fd >= 0) close(fd);
}

// Рекурсивно собирает файлы из директории
// base_dir — базовая директория (для построения относительного пути)
static void collect_files(const std::string& path,
                          const std::string& base_dir,
                          std::vector<std::pair<std::string,std::string>>& out)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return;

    if (S_ISREG(st.st_mode)) {
        // Вычисляем путь относительно base_dir
        std::string rel = path;
        if (!base_dir.empty() && path.substr(0, base_dir.size()) == base_dir) {
            rel = path.substr(base_dir.size());
            while (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
        }
        out.push_back({path, rel});
    } else if (S_ISDIR(st.st_mode)) {
        DIR* dir = opendir(path.c_str());
        if (!dir) return;
        struct dirent* ent;
        while ((ent = readdir(dir)) != nullptr) {
            std::string name = ent->d_name;
            if (name == "." || name == "..") continue;
            std::string full = path + "/" + name;
            collect_files(full, base_dir, out);
        }
        closedir(dir);
    }
}

// Структура задачи для потока добавления файла
struct AddTask {
    std::string  abs_path;        // абсолютный путь к файлу
    std::string  rel_name;        // имя в контейнере (относительный путь)
    std::string  container;       // путь к контейнеру
    const unsigned char* master;
    int          master_len;
    off_t        write_offset;    // смещение в образе для записи этого блока
};

static void* add_file_thread(void* arg) {
    AddTask* t = static_cast<AddTask*>(arg);

    // Открываем файл
    int fin = open(t->abs_path.c_str(), O_RDONLY);
    if (fin < 0) {
        std::cerr << "[ERROR] Cannot open: " << t->abs_path
                  << ": " << strerror(errno) << "\n";
        return nullptr;
    }
    struct stat st;
    fstat(fin, &st);
    uint32_t file_size = (uint32_t)st.st_size;
    uint32_t name_len  = (uint32_t)t->rel_name.size();

    // Генерируем соль и инициализируем RC4
    unsigned char salt[SALT_SIZE];
    gen_salt(salt);
    RC4State* state = rc4_alloc();
    rc4_init(state, t->master, t->master_len, salt);

    // Открываем образ для записи по смещению
    int fout = open(t->container.c_str(), O_WRONLY);
    if (fout < 0) {
        std::cerr << "[ERROR] Cannot open container: " << strerror(errno) << "\n";
        rc4_free(state);
        close(fin);
        return nullptr;
    }

    // Пишем заголовок блока
    off_t pos = t->write_offset;
    bool ok = true;
    if (pwrite(fout, &file_size, 4,                 pos) != 4)           ok = false; else pos += 4;
    if (ok && pwrite(fout, &name_len, 4,            pos) != 4)           ok = false; else pos += 4;
    if (ok && pwrite(fout, salt, SALT_SIZE,         pos) != SALT_SIZE)   ok = false; else pos += SALT_SIZE;
    if (ok && pwrite(fout, t->rel_name.c_str(), name_len, pos) != (ssize_t)name_len) ok = false; else pos += name_len;

    if (!ok) {
        std::cerr << "[ERROR] Write failed (header): " << strerror(errno) << "\n";
        rc4_free(state); close(fin); close(fout);
        return nullptr;
    }

    // Читаем, шифруем и пишем данные чанками — не держим весь файл в RAM
    static const size_t CHUNK = 4 * 1024 * 1024; // 4 МБ
    std::vector<unsigned char> buf(CHUNK);
    size_t remaining = file_size;
    while (remaining > 0) {
        size_t n = std::min(CHUNK, remaining);
        ssize_t r = read(fin, buf.data(), n);
        if (r <= 0) {
            std::cerr << "[ERROR] Read failed: " << t->abs_path << "\n";
            break;
        }
        rc4_cipher(state, buf.data(), buf.data(), (int)r);
        if (pwrite(fout, buf.data(), r, pos) != r) {
            std::cerr << "[ERROR] Write failed (data): " << strerror(errno) << "\n";
            break;
        }
        pos += r;
        remaining -= r;
    }

    rc4_free(state);
    close(fin);
    close(fout);

    std::cout << "[OK] Added: " << t->rel_name
              << " (" << file_size << " bytes)\n";
    return nullptr;
}

// Добавить файлы/директории в контейнер (все пути в одном вызове)
static int cmd_container_add(const std::string& container,
                             const std::vector<std::string>& paths,
                             const unsigned char* master,
                             int master_len)
{
    // Создаём контейнер если не существует
    int fc = open(container.c_str(), O_WRONLY | O_CREAT, 0644);
    if (fc < 0) {
        std::cerr << "[ERROR] Cannot create container: " << strerror(errno) << "\n";
        return EXIT_FAILURE;
    }
    close(fc);

    // Собираем все файлы из всех путей в один список
    std::vector<std::pair<std::string,std::string>> files;
    for (const auto& path : paths) {
        // Убираем trailing slash
        std::string clean_path = path;
        while (clean_path.size() > 1 && clean_path.back() == '/')
            clean_path.pop_back();

        struct stat st;
        if (stat(clean_path.c_str(), &st) != 0) {
            std::cerr << "[ERROR] Cannot stat: " << path << "\n";
            continue;
        }

        // base_dir — родительская директория пути
        size_t pos = clean_path.rfind('/');
        std::string base_dir = (pos == std::string::npos) ? "" : clean_path.substr(0, pos);

        size_t before = files.size();
        collect_files(clean_path, base_dir, files);
        if (files.size() == before)
            std::cerr << "[ERROR] No files found in: " << path << "\n";
    }

    if (files.empty()) {
        std::cerr << "[ERROR] No files to add\n";
        return EXIT_FAILURE;
    }

    // Узнаём текущий размер образа
    struct stat img_st;
    off_t base_offset = 0;
    if (stat(container.c_str(), &img_st) == 0)
        base_offset = img_st.st_size;

    // Вычисляем смещение для каждого файла заранее
    std::vector<AddTask> tasks(files.size());
    off_t current_offset = base_offset;
    for (size_t i = 0; i < files.size(); ++i) {
        struct stat fst;
        uint32_t file_size = 0;
        uint32_t name_len  = (uint32_t)files[i].second.size();
        if (stat(files[i].first.c_str(), &fst) == 0)
            file_size = (uint32_t)fst.st_size;

        tasks[i] = {files[i].first, files[i].second,
                    container, master, master_len, current_offset};

        current_offset += 4 + 4 + SALT_SIZE + name_len + file_size;
    }

    // Расширяем файл образа до нужного размера заранее
    int fd_trunc = open(container.c_str(), O_WRONLY);
    if (fd_trunc < 0) {
        std::cerr << "[ERROR] Cannot open container for resize: " << strerror(errno) << "\n";
        return EXIT_FAILURE;
    }
    if (ftruncate(fd_trunc, current_offset) != 0) {
        std::cerr << "[ERROR] ftruncate failed: " << strerror(errno) << "\n";
        close(fd_trunc);
        return EXIT_FAILURE;
    }
    close(fd_trunc);

    // Запускаем потоки батчами по MAX_CONTAINER_THREADS
    // Все файлы из всех путей обрабатываются в одном пуле
    size_t done = 0;
    while (done < tasks.size()) {
        size_t batch = std::min((size_t)MAX_CONTAINER_THREADS,
                                tasks.size() - done);
        pthread_t tids[MAX_CONTAINER_THREADS];
        for (size_t i = 0; i < batch; ++i)
            pthread_create(&tids[i], nullptr, add_file_thread, &tasks[done + i]);
        for (size_t i = 0; i < batch; ++i)
            pthread_join(tids[i], nullptr);
        done += batch;
    }

    std::cout << "[OK] Total added: " << files.size() << " file(s)\n";
    return EXIT_SUCCESS;
}

// Структура записи о файле в контейнере (для list/extract)
struct ContainerEntry {
    uint32_t    file_size;
    uint32_t    name_len;
    unsigned char salt[SALT_SIZE];
    std::string name;
    off_t       data_offset; // смещение данных в контейнере
};

// Читает все записи из контейнера
static bool read_entries(const std::string& container,
                         std::vector<ContainerEntry>& entries)
{
    int fd = open(container.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "[ERROR] Cannot open container: " << strerror(errno) << "\n";
        return false;
    }

    while (true) {
        ContainerEntry e;
        if (read(fd, &e.file_size, 4) != 4) break;
        if (read(fd, &e.name_len,  4) != 4) break;
        if (read(fd, e.salt, SALT_SIZE) != SALT_SIZE) break;

        std::vector<char> name_buf(e.name_len + 1, 0);
        if (read(fd, name_buf.data(), e.name_len) != (ssize_t)e.name_len) break;
        e.name = std::string(name_buf.data(), e.name_len);

        e.data_offset = lseek(fd, 0, SEEK_CUR);

        // Пропускаем данные
        lseek(fd, e.file_size, SEEK_CUR);
        entries.push_back(e);
    }

    close(fd);
    return true;
}

// Показать список файлов в контейнере
static int cmd_container_list(const std::string& container) {
    std::vector<ContainerEntry> entries;
    if (!read_entries(container, entries)) return EXIT_FAILURE;

    // Сортируем по имени
    std::sort(entries.begin(), entries.end(),
              [](const ContainerEntry& a, const ContainerEntry& b){
                  return a.name < b.name;
              });

    std::cout << "[INFO] Container : " << container << "\n"
              << "[INFO] Files     : " << entries.size() << "\n\n";
    for (const auto& e : entries) {
        std::cout << "  " << e.name
                  << "  (" << e.file_size << " bytes)\n";
    }
    return EXIT_SUCCESS;
}

// Извлечь файл из контейнера
static int cmd_container_extract(const std::string& container,
                                 const std::string& name,
                                 const std::string& out_path,
                                 const unsigned char* master,
                                 int master_len)
{
    std::vector<ContainerEntry> entries;
    if (!read_entries(container, entries)) return EXIT_FAILURE;

    const ContainerEntry* found = nullptr;
    for (const auto& e : entries) {
        if (e.name == name) { found = &e; break; }
    }
    if (!found) {
        std::cerr << "[ERROR] File not found in container: " << name << "\n";
        return EXIT_FAILURE;
    }

    // Дешифруем и записываем чанками — не держим весь файл в RAM
    int fd = open(container.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "[ERROR] Cannot open container: " << strerror(errno) << "\n";
        return EXIT_FAILURE;
    }
    lseek(fd, found->data_offset, SEEK_SET);

    int fout = open(out_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fout < 0) {
        std::cerr << "[ERROR] Cannot create output: " << strerror(errno) << "\n";
        close(fd); return EXIT_FAILURE;
    }

    RC4State* state = rc4_alloc();
    rc4_init(state, master, master_len, found->salt);

    static const size_t CHUNK = 4 * 1024 * 1024; // 4 МБ
    std::vector<unsigned char> buf(CHUNK);
    size_t remaining = found->file_size;
    while (remaining > 0) {
        size_t n = std::min(CHUNK, remaining);
        ssize_t r = read(fd, buf.data(), n);
        if (r <= 0) break;
        rc4_cipher(state, buf.data(), buf.data(), (int)r);
        write(fout, buf.data(), r);
        remaining -= r;
    }

    rc4_free(state);
    close(fd);
    close(fout);

    std::cout << "[OK] Extracted: " << name
              << " -> " << out_path
              << " (" << found->file_size << " bytes)\n";
    return EXIT_SUCCESS;
}

// Вспомогательный парсер аргументов

static std::string get_arg(int argc, char* argv[], const std::string& flag) {
    for (int i = 1; i < argc - 1; ++i)
        if (argv[i] == flag) return argv[i + 1];
    return "";
}

// main

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " -add  -key KEY -image IMAGE file1 [file2 ...] [dir/]\n"
                  << "  " << argv[0] << " -list -image IMAGE\n"
                  << "  " << argv[0] << " -get  -key KEY -image IMAGE -out RESULT FILE\n";
        return EXIT_FAILURE;
    }

    std::string cmd   = argv[1];
    std::string image = get_arg(argc, argv, "-image");
    std::string key   = get_arg(argc, argv, "-key");

    if (image.empty()) {
        std::cerr << "[ERROR] -image not specified\n";
        return EXIT_FAILURE;
    }

    // -list -image disk.img
    if (cmd == "-list")
        return cmd_container_list(image);

    // -add -key "secret" -image disk.img file1 file2 dir/
    if (cmd == "-add") {
        if (key.empty()) {
            std::cerr << "[ERROR] -key not specified\n";
            return EXIT_FAILURE;
        }
        const unsigned char* master = (const unsigned char*)key.c_str();
        int master_len = (int)key.size();

        // Собираем все пути после известных флагов
        std::vector<std::string> paths;
        bool skip_next = false;
        for (int i = 2; i < argc; ++i) {
            if (skip_next) { skip_next = false; continue; }
            std::string a = argv[i];
            if (a == "-key" || a == "-image") { skip_next = true; continue; }
            paths.push_back(a);
        }

        if (paths.empty()) {
            std::cerr << "[ERROR] No files or directories specified\n";
            return EXIT_FAILURE;
        }

        // Передаём все пути сразу — один пул потоков для всех файлов
        return cmd_container_add(image, paths, master, master_len);
    }

    // -get -key "secret" -image disk.img -out result_file file_name
    if (cmd == "-get") {
        if (key.empty()) {
            std::cerr << "[ERROR] -key not specified\n";
            return EXIT_FAILURE;
        }
        std::string out_path  = get_arg(argc, argv, "-out");
        if (out_path.empty()) {
            std::cerr << "[ERROR] -out not specified\n";
            return EXIT_FAILURE;
        }
        // file_name — последний аргумент
        std::string file_name = argv[argc - 1];

        const unsigned char* master = (const unsigned char*)key.c_str();
        int master_len = (int)key.size();
        return cmd_container_extract(image, file_name, out_path, master, master_len);
    }

    std::cerr << "[ERROR] Unknown command: " << cmd << "\n";
    return EXIT_FAILURE;
}