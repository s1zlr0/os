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
#include <queue>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <csignal>
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

    // Генерируем соль и шифруем
    unsigned char salt[SALT_SIZE];
    gen_salt(salt);

    set_key(t->master, t->master_len, salt);
    cipher(data.data(), data.data(), (int)file_size);

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

    // Дешифруем (RC4 симметричен — те же set_key + cipher)
    set_key(master, master_len, found->salt);
    cipher(data.data(), data.data(), (int)found->file_size);

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
// Task 4: шифрование файлов (без изменений от задания 4)
// ============================================================

static const size_t BUFFER_SIZE    = 8192;
static const int    LOCK_TIMEOUT_S = 5;

#ifndef WORKERS_COUNT
#define WORKERS_COUNT 4
#endif
static const int MAX_THREADS = WORKERS_COUNT;

static volatile int keep_running = 1;
static void sigint_handler(int) { keep_running = 0; }

enum Mode { AUTO, SEQUENTIAL, PARALLEL };

static pthread_mutex_t g_mutex      = PTHREAD_MUTEX_INITIALIZER;
static std::queue<std::string> g_file_queue;
static int                     g_files_done = 0;
static std::string             g_output_dir;

static bool g_deadlock_test = false;

static void simulate_deadlock_if_enabled() {
    if (g_deadlock_test) sleep(6);
}

struct FileStat {
    std::string filename;
    double      elapsed;
};

static void log_write(pthread_t tid, const std::string& filename,
                      const std::string& result, double elapsed)
{
    FILE* f = fopen("log.txt", "a");
    if (!f) return;
    time_t now = time(nullptr);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(f, "[%s] thread=%-20lu file=%-20s result=%-8s time=%.3fs\n",
            ts, static_cast<unsigned long>(tid),
            filename.c_str(), result.c_str(), elapsed);
    fclose(f);
}

static bool timed_lock(pthread_mutex_t* mutex, int thread_num) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += LOCK_TIMEOUT_S;
    int ret = pthread_mutex_timedlock(mutex, &ts);
    if (ret == ETIMEDOUT) {
        std::cerr << "[WARN] Возможная взаимоблокировка: поток " << thread_num
                  << " ожидает мьютекс более " << LOCK_TIMEOUT_S << " секунд\n";
        return false;
    }
    return (ret == 0);
}

struct SharedQueue {
    std::queue<std::vector<unsigned char>> queue;
    bool            done;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;

    SharedQueue() : done(false) {
        pthread_mutex_init(&mutex, nullptr);
        pthread_cond_init(&not_empty, nullptr);
        pthread_cond_init(&not_full, nullptr);
    }
    ~SharedQueue() {
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&not_empty);
        pthread_cond_destroy(&not_full);
    }
};

struct ProducerArgs { const char* input_path;  SharedQueue* queue; };
struct ConsumerArgs { const char* output_path; SharedQueue* queue; };

static void* producer_thread(void* arg) {
    ProducerArgs* a = static_cast<ProducerArgs*>(arg);
    FILE* fin = fopen(a->input_path, "rb");
    if (!fin) {
        std::cerr << "[ERROR] Cannot open: " << a->input_path << "\n";
        pthread_mutex_lock(&a->queue->mutex);
        a->queue->done = true;
        pthread_cond_signal(&a->queue->not_empty);
        pthread_mutex_unlock(&a->queue->mutex);
        return nullptr;
    }
    while (keep_running) {
        std::vector<unsigned char> buf(BUFFER_SIZE);
        size_t n = fread(buf.data(), 1, BUFFER_SIZE, fin);
        if (n == 0) break;
        buf.resize(n);
        cipher(buf.data(), buf.data(), static_cast<int>(n));
        pthread_mutex_lock(&a->queue->mutex);
        while (!a->queue->queue.empty() && keep_running)
            pthread_cond_wait(&a->queue->not_full, &a->queue->mutex);
        if (!keep_running) { pthread_mutex_unlock(&a->queue->mutex); break; }
        a->queue->queue.push(std::move(buf));
        pthread_cond_signal(&a->queue->not_empty);
        pthread_mutex_unlock(&a->queue->mutex);
    }
    fclose(fin);
    pthread_mutex_lock(&a->queue->mutex);
    a->queue->done = true;
    pthread_cond_signal(&a->queue->not_empty);
    pthread_mutex_unlock(&a->queue->mutex);
    return nullptr;
}

static void* consumer_thread(void* arg) {
    ConsumerArgs* a = static_cast<ConsumerArgs*>(arg);
    FILE* fout = fopen(a->output_path, "wb");
    if (!fout) {
        std::cerr << "[ERROR] Cannot open output: " << a->output_path << "\n";
        pthread_mutex_lock(&a->queue->mutex);
        a->queue->done = true;
        pthread_mutex_unlock(&a->queue->mutex);
        return nullptr;
    }
    while (true) {
        pthread_mutex_lock(&a->queue->mutex);
        while (a->queue->queue.empty() && !a->queue->done && keep_running)
            pthread_cond_wait(&a->queue->not_empty, &a->queue->mutex);
        if (a->queue->queue.empty() && (a->queue->done || !keep_running)) {
            pthread_mutex_unlock(&a->queue->mutex);
            break;
        }
        std::vector<unsigned char> buf = std::move(a->queue->queue.front());
        a->queue->queue.pop();
        pthread_cond_signal(&a->queue->not_full);
        pthread_mutex_unlock(&a->queue->mutex);
        if (fwrite(buf.data(), 1, buf.size(), fout) != buf.size()) {
            std::cerr << "[ERROR] Write error: " << strerror(errno) << "\n";
            break;
        }
    }
    fclose(fout);
    return nullptr;
}

static double process_file(const std::string& input, const std::string& output) {
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    SharedQueue  queue;
    ProducerArgs prod { input.c_str(),  &queue };
    ConsumerArgs cons { output.c_str(), &queue };
    pthread_t producer_tid, consumer_tid;
    pthread_create(&producer_tid, nullptr, producer_thread, &prod);
    pthread_create(&consumer_tid, nullptr, consumer_thread, &cons);
    pthread_join(producer_tid, nullptr);
    pthread_join(consumer_tid, nullptr);

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    return (t_end.tv_sec  - t_start.tv_sec)
         + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
}

static std::string base_name(const std::string& path) {
    size_t pos = path.rfind('/');
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

static bool ensure_dir(const std::string& dir) {
    struct stat st;
    if (stat(dir.c_str(), &st) == 0) return S_ISDIR(st.st_mode);
    return mkdir(dir.c_str(), 0755) == 0;
}

static long get_file_size(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0) ? static_cast<long>(st.st_size) : -1;
}

static void print_stats(const std::string& mode_name,
                        const std::vector<FileStat>& stats,
                        double total_time)
{
    double avg = stats.empty() ? 0.0 : total_time / stats.size();
    std::cout << "\nStatistics [" << mode_name << "]\n"
              << "  Files processed : " << stats.size() << "\n"
              << "  Total time      : " << total_time << "s\n"
              << "  Avg per file    : " << avg << "s\n";
}

static double run_sequential(const std::vector<std::string>& files,
                             const std::string& output_dir,
                             std::vector<FileStat>& stats)
{
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    for (const auto& f : files) {
        if (!keep_running) break;
        std::string out = output_dir + base_name(f);
        std::cout << "[SEQ] Processing: " << f << "\n";
        double elapsed = process_file(f, out);
        stats.push_back({f, elapsed});
        std::cout << "[SEQ] Done: " << f << " (" << elapsed << "s)\n";

        pthread_mutex_lock(&g_mutex);
        ++g_files_done;
        log_write(pthread_self(), f, "OK", elapsed);
        pthread_mutex_unlock(&g_mutex);
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    return (t_end.tv_sec  - t_start.tv_sec)
         + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
}

struct WorkerArgs {
    int                   thread_num;
    std::vector<FileStat>* stats;
};

static void* worker_thread(void* arg) {
    WorkerArgs* a   = static_cast<WorkerArgs*>(arg);
    pthread_t   tid = pthread_self();

    while (keep_running) {
        if (!timed_lock(&g_mutex, a->thread_num)) {
            std::cerr << "[Thread " << a->thread_num
                      << "] Deadlock detected — aborting thread.\n";
            keep_running = 0;
            return nullptr;
        }
        if (g_file_queue.empty()) {
            pthread_mutex_unlock(&g_mutex);
            break;
        }
        std::string input_path = g_file_queue.front();
        g_file_queue.pop();
        simulate_deadlock_if_enabled();
        pthread_mutex_unlock(&g_mutex);

        std::string output_path = g_output_dir + base_name(input_path);
        std::cout << "[Thread " << a->thread_num << " / tid="
                  << static_cast<unsigned long>(tid)
                  << "] Processing: " << input_path << "\n";

        double elapsed = process_file(input_path, output_path);
        std::string result = keep_running ? "OK" : "ABORTED";

        if (!timed_lock(&g_mutex, a->thread_num)) {
            std::cerr << "[Thread " << a->thread_num
                      << "] Deadlock detected — aborting thread.\n";
            keep_running = 0;
            return nullptr;
        }
        ++g_files_done;
        int done = g_files_done;
        log_write(tid, input_path, result, elapsed);
        pthread_mutex_unlock(&g_mutex);
        a->stats->push_back({input_path, elapsed});

        std::cout << "[Thread " << a->thread_num << "] Done: "
                  << input_path << " (" << elapsed << "s)"
                  << " [" << done << " file(s) completed]\n";
    }
    return nullptr;
}

static double run_parallel(const std::vector<std::string>& files,
                           const std::string& output_dir,
                           std::vector<FileStat>& stats)
{
    for (const auto& f : files)
        g_file_queue.push(f);
    g_output_dir  = output_dir;
    g_files_done  = 0;

    std::vector<std::vector<FileStat>> thread_stats(MAX_THREADS);

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    pthread_t  tids[MAX_THREADS];
    WorkerArgs wargs[MAX_THREADS];
    for (int i = 0; i < MAX_THREADS; ++i) {
        wargs[i].thread_num = i + 1;
        wargs[i].stats      = &thread_stats[i];
        pthread_create(&tids[i], nullptr, worker_thread, &wargs[i]);
    }
    for (int i = 0; i < MAX_THREADS; ++i)
        pthread_join(tids[i], nullptr);

    clock_gettime(CLOCK_MONOTONIC, &t_end);

    for (auto& ts : thread_stats)
        for (auto& s : ts)
            stats.push_back(s);

    return (t_end.tv_sec  - t_start.tv_sec)
         + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
}

// ============================================================
// main
// ============================================================

int main(int argc, char* argv[]) {

    // Task 6: контейнер команды
    // ./secure_copy --add container path master_key
    // ./secure_copy --list container
    // ./secure_copy --extract container file_name out_path master_key
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

    // Task 4: шифрование файлов
    if (argc < 4) {
        std::cerr << "Task 4 usage:\n"
                  << "  " << argv[0]
                  << " [--mode=sequential|parallel] [--deadlock-test]"
                  << " file1 ... output_dir/ key\n\n"
                  << "Task 6 usage:\n"
                  << "  " << argv[0] << " --add    container path master_key\n"
                  << "  " << argv[0] << " --list   container\n"
                  << "  " << argv[0] << " --extract container file_name out_path master_key\n";
        return EXIT_FAILURE;
    }

    int  arg_offset = 0;
    Mode mode       = AUTO;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--mode=sequential") { mode = SEQUENTIAL; ++arg_offset; }
        else if (a == "--mode=parallel")   { mode = PARALLEL;   ++arg_offset; }
        else if (a == "--deadlock-test")   { g_deadlock_test = true; ++arg_offset; }
        else break;
    }

    const unsigned char* master     = (const unsigned char*)argv[argc - 1];
    int                  master_len = (int)strlen(argv[argc - 1]);
    std::string output_dir = argv[argc - 2];
    int         num_files  = argc - 3 - arg_offset;

    if (num_files <= 0) {
        std::cerr << "[ERROR] No input files specified.\n";
        return EXIT_FAILURE;
    }

    if (output_dir.back() != '/') output_dir += '/';

    if (!ensure_dir(output_dir)) {
        std::cerr << "[ERROR] Cannot create directory: " << output_dir << "\n";
        return EXIT_FAILURE;
    }

    std::vector<std::string> files;
    for (int i = 1 + arg_offset; i <= num_files + arg_offset; ++i) {
        if (get_file_size(argv[i]) < 0) {
            std::cerr << "[ERROR] File not found: " << argv[i] << "\n";
            return EXIT_FAILURE;
        }
        files.push_back(argv[i]);
    }

    if (mode == AUTO)
        mode = (num_files < 5) ? SEQUENTIAL : PARALLEL;

    std::string mode_name = (mode == SEQUENTIAL) ? "sequential" : "parallel";
    std::cout << "[INFO] Files   : " << num_files << "\n"
              << "[INFO] Mode    : " << mode_name << "\n"
              << "[INFO] Output  : " << output_dir << "\n"
              << "[INFO] Key     : " << argv[argc - 1] << "\n"
              << "[INFO] Press Ctrl+C to cancel\n\n";

    // Для task4 используем RC4 без соли (соль = нули)
    unsigned char zero_salt[SALT_SIZE] = {};
    set_key(master, master_len, zero_salt);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, nullptr);

    std::vector<FileStat> stats;
    double total_time = 0.0;

    if (mode == SEQUENTIAL)
        total_time = run_sequential(files, output_dir, stats);
    else
        total_time = run_parallel(files, output_dir, stats);

    if (!keep_running) {
        std::cout << "\nОперация прервана пользователем\n";
        return EXIT_FAILURE;
    }

    print_stats(mode_name, stats, total_time);

    if (argc > 1) {
        bool was_auto = true;
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--mode=sequential" || a == "--mode=parallel") {
                was_auto = false; break;
            }
        }

        if (was_auto) {
            std::cout << "\nRunning alternative mode for comparison\n";
            Mode alt_mode = (mode == SEQUENTIAL) ? PARALLEL : SEQUENTIAL;
            std::string alt_name = (alt_mode == SEQUENTIAL) ? "sequential" : "parallel";

            g_files_done = 0;
            keep_running = 1;
            while (!g_file_queue.empty()) g_file_queue.pop();

            std::string alt_output = output_dir + "alt/";
            ensure_dir(alt_output);

            // Переинициализируем RC4 для повторного прохода
            set_key(master, master_len, zero_salt);

            std::vector<FileStat> alt_stats;
            double alt_time = 0.0;

            if (alt_mode == SEQUENTIAL)
                alt_time = run_sequential(files, alt_output, alt_stats);
            else
                alt_time = run_parallel(files, alt_output, alt_stats);

            print_stats(alt_name, alt_stats, alt_time);

            std::cout << "\nComparison\n"
                      << "  " << mode_name << " : " << total_time << "s\n"
                      << "  " << alt_name  << " : " << alt_time   << "s\n"
                      << "  Faster: "
                      << (total_time <= alt_time ? mode_name : alt_name)
                      << " by " << std::abs(total_time - alt_time) << "s\n";
        }
    }

    std::cout << "\n[OK] All done.\n"
              << "[INFO] Log written to: log.txt\n";

    return EXIT_SUCCESS;
}