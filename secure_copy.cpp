
#include <iostream>
#include <queue>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <pthread.h>
#include <sys/stat.h>

#include "caesar.h"

// ── Constants
static const size_t BUFFER_SIZE = 8192; // buffer size in bytes

// ── Running flag (volatile - written from signal handler)
static volatile int keep_running = 1;

// ── SIGINT handler (Ctrl+C)
static void sigint_handler(int /*sig*/) {
    keep_running = 0;
}

// ── Shared queue between Producer and Consumer
struct SharedQueue {
    std::queue<std::vector<unsigned char>> queue; // queue of buffers
    bool            done;        // producer finished reading

    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;   // consumer waits for data
    pthread_cond_t  not_full;    // producer waits when queue has item

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

// ── Thread arguments
struct ProducerArgs {
    const char*  input_path;
    SharedQueue* queue;
};

struct ConsumerArgs {
    const char*  output_path;
    SharedQueue* queue;
};

// ── Producer thread
// Reads input file in 8192-byte buffers, encrypts, pushes into queue.
static void* producer_thread(void* arg) {
    ProducerArgs* a = static_cast<ProducerArgs*>(arg);

    FILE* fin = fopen(a->input_path, "rb");
    if (!fin) {
        std::cerr << "\n[ERROR] Cannot open input file: " << a->input_path
                  << " (" << strerror(errno) << ")\n";
        pthread_mutex_lock(&a->queue->mutex);
        a->queue->done = true;
        pthread_cond_signal(&a->queue->not_empty);
        pthread_mutex_unlock(&a->queue->mutex);
        return nullptr;
    }

    while (keep_running) {
        // Read one buffer from file
        std::vector<unsigned char> buf(BUFFER_SIZE);
        size_t n = fread(buf.data(), 1, BUFFER_SIZE, fin);
        if (n == 0) break; // EOF
        buf.resize(n);

        // Encrypt buffer in-place using libcaesar
        caesar(buf.data(), buf.data(), static_cast<int>(n));

        // Push into queue — wait if queue already has one item
        pthread_mutex_lock(&a->queue->mutex);
        while (!a->queue->queue.empty() && keep_running)
            pthread_cond_wait(&a->queue->not_full, &a->queue->mutex);

        if (!keep_running) {
            pthread_mutex_unlock(&a->queue->mutex);
            break;
        }

        a->queue->queue.push(std::move(buf));
        pthread_cond_signal(&a->queue->not_empty);
        pthread_mutex_unlock(&a->queue->mutex);
    }

    fclose(fin);

    // Signal consumer that no more data is coming
    pthread_mutex_lock(&a->queue->mutex);
    a->queue->done = true;
    pthread_cond_signal(&a->queue->not_empty);
    pthread_mutex_unlock(&a->queue->mutex);

    return nullptr;
}

// ── Consumer thread
// Pops buffers from queue, writes to output file.
static void* consumer_thread(void* arg) {
    ConsumerArgs* a = static_cast<ConsumerArgs*>(arg);

    FILE* fout = fopen(a->output_path, "wb");
    if (!fout) {
        std::cerr << "\n[ERROR] Cannot open output file: " << a->output_path
                  << " (" << strerror(errno) << ")\n";
        pthread_mutex_lock(&a->queue->mutex);
        a->queue->done = true;
        pthread_mutex_unlock(&a->queue->mutex);
        return nullptr;
    }

    while (true) {
        pthread_mutex_lock(&a->queue->mutex);

        // Wait for data or done signal
        while (a->queue->queue.empty() && !a->queue->done && keep_running)
            pthread_cond_wait(&a->queue->not_empty, &a->queue->mutex);

        // Exit if nothing left
        if (a->queue->queue.empty() && (a->queue->done || !keep_running)) {
            pthread_mutex_unlock(&a->queue->mutex);
            break;
        }

        // Pop buffer from queue
        std::vector<unsigned char> buf = std::move(a->queue->queue.front());
        a->queue->queue.pop();

        pthread_cond_signal(&a->queue->not_full);
        pthread_mutex_unlock(&a->queue->mutex);

        // Write buffer to output file
        size_t n = buf.size();
        if (fwrite(buf.data(), 1, n, fout) != n) {
            std::cerr << "\n[ERROR] Write error: " << strerror(errno) << "\n";
            break;
        }
    }

    fclose(fout);
    return nullptr;
}

// ── Get file size
static long get_file_size(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return static_cast<long>(st.st_size);
}

// ── main
int main(int argc, char* argv[]) {
    // Check arguments
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input> <output> <key>\n"
                  << "  <input>   - source file\n"
                  << "  <output>  - destination file\n"
                  << "  <key>     - encryption key (integer 0-255)\n\n"
                  << "Example:\n"
                  << "  " << argv[0] << " input.txt encrypted.bin 42\n"
                  << "  " << argv[0] << " encrypted.bin restored.txt 42\n";
        return EXIT_FAILURE;
    }

    const char* input_path  = argv[1];
    const char* output_path = argv[2];
    int         key         = atoi(argv[3]) & 0xFF;

    // Check input file exists
    long file_size = get_file_size(input_path);
    if (file_size < 0) {
        std::cerr << "[ERROR] Input file not found: " << input_path << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "[INFO] Input  : " << input_path  << " (" << file_size << " bytes)\n"
              << "[INFO] Output : " << output_path << "\n"
              << "[INFO] Key    : " << key << "\n"
              << "[INFO] Press Ctrl+C to cancel\n";

    // Set encryption key in libcaesar
    set_key(static_cast<char>(key));

    // Install SIGINT handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, nullptr);

    // Create shared queue
    SharedQueue queue;

    // Thread arguments
    ProducerArgs prod_args { input_path,  &queue };
    ConsumerArgs cons_args { output_path, &queue };

    // Start exactly two threads (as required)
    pthread_t producer_tid, consumer_tid;
    pthread_create(&producer_tid, nullptr, producer_thread, &prod_args);
    pthread_create(&consumer_tid, nullptr, consumer_thread, &cons_args);

    // Wait for both threads to finish
    pthread_join(producer_tid, nullptr);
    pthread_join(consumer_tid, nullptr);

    // Handle Ctrl+C
    if (!keep_running) {
        std::cout << "\nОперация прервана пользователем\n";

        // Delete incomplete output file
        if (remove(output_path) == 0)
            std::cout << "[INFO] Output file deleted: " << output_path << "\n";
        else
            std::cerr << "[WARN] Could not delete output file: " << output_path << "\n";

        return EXIT_FAILURE;
    }

    std::cout << "[OK] Done. " << file_size << " bytes processed.\n";

    return EXIT_SUCCESS;
}