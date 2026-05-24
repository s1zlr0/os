/**
 * secure_copy.cpp — Task 4 + Task 6
 *
 * Task 4: шифрование файлов с параллельной обработкой (pthread).
 * Task 6: контейнер для зашифрованных файлов на RC4.
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

// ============================================================
// Task 6: контейнер файлов с RC4-шифрованием
// ============================================================

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
            if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
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
    std::string  abs_path;   // абсолютный путь к файлу
    std::string  rel_name;   // имя в контейнере (относительный путь)
    std::string  container;  // путь к контейнеру
    const unsigned char* master;
    int          master_len;
    pthread_mutex_t* fd_mutex; // мьютекс для записи в контейнер
};

static void* add_file_thread(void* arg) {
    AddTask* t = static_cast<AddTask*>(arg);

    // Читаем файл
    int fin = open(t->abs_path.c_str(), O_RDONLY);
    if (fin < 0) {
        std::cerr << "[ERROR] Cannot open: " << t->abs_path
                  << ": " << strerror(errno) << "\n";
        return nullptr;
    }
    struct stat st;
    fstat(fin, &st);
    uint32_t file_size = (uint32_t)st.st_size;
    std::vector<unsigned char> data(file_size);
    if (read(fin, data.data(), file_size) != (ssize_t)file_size) {
        std::cerr << "[ERROR] Read failed: " << t->abs_path << "\n";
        close(fin); return nullptr;
    }
    close(fin);

    // Генерируем соль, создаём своё состояние RC4 для этого файла
    unsigned char salt[SALT_SIZE];
    gen_salt(salt);

    RC4State* state = rc4_alloc();
    rc4_init(state, t->master, t->master_len, salt);
    rc4_cipher(state, data.data(), data.data(), (int)file_size);
    rc4_free(state);

    // Формируем заголовок блока
    uint32_t name_len = (uint32_t)t->rel_name.size();

    // Пишем в контейнер под мьютексом
    pthread_mutex_lock(t->fd_mutex);

    int fout = open(t->container.c_str(), O_WRONLY | O_APPEND);
    if (fout < 0) {
        std::cerr << "[ERROR] Cannot open container: " << strerror(errno) << "\n";
        pthread_mutex_unlock(t->fd_mutex);
        return nullptr;
    }

    // [4] размер файла
    write(fout, &file_size, 4);
    // [4] длина имени
    write(fout, &name_len, 4);
    // [16] соль
    write(fout, salt, SALT_SIZE);
    // [N] имя файла
    write(fout, t->rel_name.c_str(), name_len);
    // [M] данные
    write(fout, data.data(), file_size);

    close(fout);
    pthread_mutex_unlock(t->fd_mutex);

    std::cout << "[OK] Added: " << t->rel_name
              << " (" << file_size << " bytes)\n";
    return nullptr;
}

// Добавить файлы/директорию в контейнер
static int cmd_container_add(const std::string& container,
                             const std::string& path,
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

    // Собираем список файлов
    std::vector<std::pair<std::string,std::string>> files;
    // base_dir = родительская директория пути
    struct stat st;
    stat(path.c_str(), &st);
    std::string base_dir;
    if (S_ISDIR(st.st_mode)) {
        base_dir = path;
        // убираем trailing slash
        if (!base_dir.empty() && base_dir.back() == '/')
            base_dir.pop_back();
        // base_dir — родитель, чтобы имя директории входило в путь
        size_t pos = base_dir.rfind('/');
        base_dir = (pos == std::string::npos) ? "" : base_dir.substr(0, pos);
    } else {
        size_t pos = path.rfind('/');
        base_dir = (pos == std::string::npos) ? "" : path.substr(0, pos);
    }
    collect_files(path, base_dir, files);

    if (files.empty()) {
        std::cerr << "[ERROR] No files found in: " << path << "\n";
        return EXIT_FAILURE;
    }

    pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;

    // Обрабатываем батчами по MAX_CONTAINER_THREADS потоков
    std::vector<AddTask> tasks(files.size());
    for (size_t i = 0; i < files.size(); ++i) {
        tasks[i] = {files[i].first, files[i].second,
                    container, master, master_len, &fd_mutex};
    }

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

    pthread_mutex_destroy(&fd_mutex);
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

    // Читаем зашифрованные данные
    int fd = open(container.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "[ERROR] Cannot open container: " << strerror(errno) << "\n";
        return EXIT_FAILURE;
    }
    lseek(fd, found->data_offset, SEEK_SET);
    std::vector<unsigned char> data(found->file_size);
    if (read(fd, data.data(), found->file_size) != (ssize_t)found->file_size) {
        std::cerr << "[ERROR] Read failed\n";
        close(fd); return EXIT_FAILURE;
    }
    close(fd);

    // Дешифруем — создаём своё состояние RC4 с той же солью
    RC4State* state = rc4_alloc();
    rc4_init(state, master, master_len, found->salt);
    rc4_cipher(state, data.data(), data.data(), (int)found->file_size);
    rc4_free(state);

    // Создаём выходной файл
    int fout = open(out_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fout < 0) {
        std::cerr << "[ERROR] Cannot create output: " << strerror(errno) << "\n";
        return EXIT_FAILURE;
    }
    write(fout, data.data(), found->file_size);
    close(fout);

    std::cout << "[OK] Extracted: " << name
              << " -> " << out_path
              << " (" << found->file_size << " bytes)\n";
    return EXIT_SUCCESS;
}

// ============================================================
// main
// ============================================================

int main(int argc, char* argv[]) {
    if (argc >= 2) {
        std::string cmd = argv[1];

        if (cmd == "--list" && argc == 3)
            return cmd_container_list(argv[2]);

        if (cmd == "--add" && argc == 5) {
            const unsigned char* master = (const unsigned char*)argv[4];
            int master_len = (int)strlen(argv[4]);
            return cmd_container_add(argv[2], argv[3], master, master_len);
        }

        if (cmd == "--extract" && argc == 6) {
            const unsigned char* master = (const unsigned char*)argv[5];
            int master_len = (int)strlen(argv[5]);
            return cmd_container_extract(argv[2], argv[3], argv[4],
                                         master, master_len);
        }
    }

    std::cerr << "Usage:\n"
              << "  " << argv[0] << " --add     container path master_key\n"
              << "  " << argv[0] << " --list    container\n"
              << "  " << argv[0] << " --extract container file_name out_path master_key\n";
    return EXIT_FAILURE;
}