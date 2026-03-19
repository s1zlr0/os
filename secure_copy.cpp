/**
 * secure_copy.cpp - Task 3
 * 3 worker threads, each picks files from shared queue until empty.
 * Single mutex protects queue, counter and log.
 * Usage: ./secure_copy file1 file2 ... output_dir/ key
 */

#include <iostream>
#include <queue>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <ctime>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "caesar.h"

static const size_t BUFFER_SIZE    = 8192;
static const int    NUM_THREADS    = 3;
static const int    LOCK_TIMEOUT_S = 5;

static volatile int keep_running = 1;

static void sigint_handler(int /*sig*/) { keep_running = 0; }

// Single mutex protects: g_file_queue, g_files_done, log writes
static pthread_mutex_t g_mutex      = PTHREAD_MUTEX_INITIALIZER;
static std::queue<std::string> g_file_queue;
static int                     g_files_done = 0;
static std::string             g_output_dir;

// Flag to enable deadlock simulation
static bool g_deadlock_test = false;

// Deadlock simulation: hold mutex for 6s so other threads timeout
static void simulate_deadlock_if_enabled() {
    if (g_deadlock_test)
        sleep(6);
}

// Append one line to log.txt — called while g_mutex is held
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

// Try to lock mutex with 5s timeout. On timeout: print warning, return false.
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

// Per-file queue for producer/consumer (from Task 2, unchanged)
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
        caesar(buf.data(), buf.data(), static_cast<int>(n));
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

static bool process_file(const std::string& input, const std::string& output) {
    SharedQueue  queue;
    ProducerArgs prod { input.c_str(),  &queue };
    ConsumerArgs cons { output.c_str(), &queue };
    pthread_t producer_tid, consumer_tid;
    pthread_create(&producer_tid, nullptr, producer_thread, &prod);
    pthread_create(&consumer_tid, nullptr, consumer_thread, &cons);
    pthread_join(producer_tid, nullptr);
    pthread_join(consumer_tid, nullptr);
    return keep_running;
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

struct WorkerArgs { int thread_num; };

static void* worker_thread(void* arg) {
    WorkerArgs* a   = static_cast<WorkerArgs*>(arg);
    pthread_t   tid = pthread_self();

    while (keep_running) {
        // Get next file from queue
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
        simulate_deadlock_if_enabled(); // hold mutex to trigger timeout in other threads
        pthread_mutex_unlock(&g_mutex);

        std::string output_path = g_output_dir + base_name(input_path);
        std::cout << "[Thread " << a->thread_num << " / tid="
                  << static_cast<unsigned long>(tid)
                  << "] Processing: " << input_path << "\n";

        struct timespec t_start, t_end;
        clock_gettime(CLOCK_MONOTONIC, &t_start);
        bool ok = process_file(input_path, output_path);
        clock_gettime(CLOCK_MONOTONIC, &t_end);
        double elapsed = (t_end.tv_sec  - t_start.tv_sec)
                       + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;

        std::string result = ok ? "OK" : "ABORTED";

        // Update counter and write log
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

        std::cout << "[Thread " << a->thread_num << "] Done: "
                  << input_path << " (" << elapsed << "s)"
                  << " [" << done << " file(s) completed]\n";
    }

    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " file1 [file2 ...] output_dir/ key\n";
        return EXIT_FAILURE;
    }

    // Check for optional --deadlock-test flag as first argument
    int arg_offset = 0;
    if (argc >= 2 && std::string(argv[1]) == "--deadlock-test") {
        g_deadlock_test = true;
        arg_offset = 1;
        std::cout << "[INFO] Deadlock simulation enabled\n";
    }

    int         key        = atoi(argv[argc - 1]) & 0xFF;
    std::string output_dir = argv[argc - 2];
    int         num_files  = argc - 3 - arg_offset;

    if (output_dir.back() != '/') output_dir += '/';

    if (!ensure_dir(output_dir)) {
        std::cerr << "[ERROR] Cannot create directory: " << output_dir << "\n";
        return EXIT_FAILURE;
    }

    for (int i = 1 + arg_offset; i <= num_files + arg_offset; ++i) {
        if (get_file_size(argv[i]) < 0) {
            std::cerr << "[ERROR] File not found: " << argv[i] << "\n";
            return EXIT_FAILURE;
        }
        g_file_queue.push(argv[i]);
    }

    g_output_dir = output_dir;

    std::cout << "[INFO] Files   : " << num_files << "\n"
              << "[INFO] Threads : " << NUM_THREADS << "\n"
              << "[INFO] Output  : " << output_dir << "\n"
              << "[INFO] Key     : " << key << "\n"
              << "[INFO] Press Ctrl+C to cancel\n\n";

    set_key(static_cast<char>(key));

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, nullptr);

    pthread_t  tids[NUM_THREADS];
    WorkerArgs wargs[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; ++i) {
        wargs[i].thread_num = i + 1;
        pthread_create(&tids[i], nullptr, worker_thread, &wargs[i]);
    }
    for (int i = 0; i < NUM_THREADS; ++i)
        pthread_join(tids[i], nullptr);

    if (!keep_running) {
        std::cout << "\nОперация прервана пользователем\n";
        return EXIT_FAILURE;
    }

    std::cout << "\n[OK] All done. Files processed: "
              << g_files_done << "/" << num_files << "\n";
    std::cout << "[INFO] Log written to: log.txt\n";

    return EXIT_SUCCESS;
}