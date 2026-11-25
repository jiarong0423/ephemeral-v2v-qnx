/*
 * test_qnx_probe - what does THIS image contain, and what works in it? It answers the open question "HAM: check the packages
 * first" with measurements, not claims. [PASS] = the call worked and its effect was read back, [INFO] = a fact (with the exact
 * errno where there is one), [SKIP] = not available in this image (never counted as a pass).
 *   P1 slog2           slog2_register + slog2f, read back with slog2info
 *   P2 HAM / APS       is there a ham, libham, aps binary or library, in /proc/boot, /system/bin, /usr/bin, /usr/sbin, /system/lib?
 *   P3 typed memory    posix_typed_mem_open on the usual names; the allocatable size of the one that opens
 *   P4 image listing   every file name in the boot image and bin directories that contains ham, aps, slog, trace or mem
 *   P5 mutex protocol  the default protocol of a mutex attribute, and that PTHREAD_PRIO_INHERIT can be set and read back
 * The program exits 0 unless a mechanism that worked misbehaved. QNX only; other systems print [SKIP] and exit 0.
 * Taken after the structure of the research repository's tests/test_qnx_probe.c, reduced to the questions of this project.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#if defined(__QNX__) || defined(__QNXNTO__)

#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/slog2.h>

static int g_failures = 0, g_skips = 0;
#define CHECK(cond, msg) do { if (cond) printf("    [PASS] %s\n", msg); else { printf("    [FAIL] %s (line %d)\n", msg, __LINE__); g_failures++; } } while (0)
#define INFO(...) do { printf("    [INFO] "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define SKIPC(...) do { printf("    [SKIP] "); printf(__VA_ARGS__); printf("\n"); g_skips++; } while (0)

static int exists(const char *p) { return access(p, F_OK) == 0; }

static void probe_slog2(void) {
    printf("[P1] slog2 (slogger2)\n");
    void *lib = dlopen("libslog2.so.1", RTLD_NOW);
    if (!lib) lib = dlopen("libslog2.so", RTLD_NOW);
    if (!lib) { SKIPC("libslog2 cannot be loaded in this image: %s", dlerror()); return; }
    int (*p_register)(const slog2_buffer_set_config_t *, slog2_buffer_t *, uint32_t) = (int (*)(const slog2_buffer_set_config_t *, slog2_buffer_t *, uint32_t))dlsym(lib, "slog2_register");
    int (*p_slog2f)(slog2_buffer_t, uint16_t, uint8_t, const char *, ...) = (int (*)(slog2_buffer_t, uint16_t, uint8_t, const char *, ...))dlsym(lib, "slog2f");
    if (!p_register || !p_slog2f) { SKIPC("libslog2 loaded but slog2_register/slog2f not found"); return; }
    slog2_buffer_set_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.num_buffers = 1;
    cfg.buffer_set_name = "v2vprobe";
    cfg.verbosity_level = SLOG2_INFO;
    cfg.buffer_config[0].buffer_name = "main";
    cfg.buffer_config[0].num_pages = 1;
    slog2_buffer_t h[1];
    errno = 0;
    int rc = p_register(&cfg, h, 0);
    if (rc != 0) { SKIPC("slog2_register failed, errno %d (%s)", errno, strerror(errno)); return; }
    char marker[64];
    snprintf(marker, sizeof(marker), "v2v-port-probe-marker-%d", (int)getpid());
    CHECK(p_slog2f(h[0], 1, SLOG2_INFO, "%s", marker) == 0, "slog2f wrote a log line into the slogger2 buffer");
    usleep(300000);
    const char *tools[] = {"/system/bin/slog2info", "/usr/bin/slog2info", "/bin/slog2info", NULL};
    const char *tool = NULL;
    for (int i = 0; tools[i] && !tool; ++i) if (exists(tools[i])) tool = tools[i];
    if (!tool) { SKIPC("slog2info is not in this image: the line was written but cannot be read back here"); return; }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s -b v2vprobe 2>&1", tool);
    FILE *f = popen(cmd, "r");
    char buf[4096];
    size_t n = 0;
    if (f) { n = fread(buf, 1, sizeof(buf) - 1, f); pclose(f); }
    buf[n] = 0;
    INFO("%s -b v2vprobe returned %zu bytes", tool, n);
    CHECK(strstr(buf, marker) != NULL, "the line written with slog2f is read back with slog2info");
}

static void probe_ham_aps(void) {
    printf("[P2] High Availability Manager (HAM) and Adaptive Partitioning (APS)\n");
    static const char *dirs[] = {"/proc/boot", "/system/bin", "/usr/bin", "/usr/sbin", "/bin", "/sbin", NULL};
    static const char *libs[] = {"/system/lib/libham.so", "/system/lib/libham.so.1", "/usr/lib/libham.so", "/usr/lib/libham.so.1", "/proc/boot/libham.so", "/proc/boot/libham.so.1", NULL};
    int ham = 0, aps = 0;
    char path[256];
    for (int d = 0; dirs[d]; ++d) {
        snprintf(path, sizeof(path), "%s/ham", dirs[d]);
        if (exists(path)) { ham = 1; INFO("found %s", path); }
        snprintf(path, sizeof(path), "%s/aps", dirs[d]);
        if (exists(path)) { aps = 1; INFO("found %s", path); }
    }
    for (int i = 0; libs[i]; ++i) if (exists(libs[i])) { ham = 1; INFO("found %s", libs[i]); }
    INFO("HAM (ham binary or libham) in this image: %s", ham ? "YES" : "NO");
    INFO("APS (aps binary) in this image: %s", aps ? "YES" : "NO");
    if (!ham) SKIPC("HAM is not in this image: supervision uses a plain respawn (v2v-supervisor), no HAM claim is made");
    if (!aps) SKIPC("aps is not in this image: no adaptive partitioning is used or claimed");
}

static void probe_typed(void) {
    printf("[P3] POSIX typed memory\n");
    static const char *names[] = {"/sysram", "sysram", "/ram/dma", "/dma", NULL};
    int opened = 0;
    for (int i = 0; names[i]; ++i) {
        errno = 0;
        int fd = posix_typed_mem_open(names[i], O_RDWR, POSIX_TYPED_MEM_ALLOCATE);
        if (fd < 0) { INFO("posix_typed_mem_open(\"%s\", ALLOCATE) -> -1, errno %d (%s)", names[i], errno, strerror(errno)); continue; }
        opened++;
        struct posix_typed_mem_info info;
        memset(&info, 0, sizeof(info));
        if (posix_typed_mem_get_info(fd, &info) == 0) INFO("posix_typed_mem_open(\"%s\", ALLOCATE) -> fd %d; allocatable %llu bytes", names[i], fd, (unsigned long long)info.posix_tmi_length);
        else INFO("posix_typed_mem_open(\"%s\", ALLOCATE) -> fd %d; get_info errno %d", names[i], fd, errno);
        void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(m != MAP_FAILED, "a page can be allocated from this typed memory object");
        if (m != MAP_FAILED) munmap(m, 4096);
        close(fd);
    }
    if (opened == 0) SKIPC("no typed memory object could be opened on this image");
    CHECK(opened >= 1, "at least one typed memory object (the one the secure page uses) opens");
}

static void list_matches(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) { INFO("%s: cannot open (%s)", dir, strerror(errno)); return; }
    struct dirent *e;
    int n = 0, total = 0;
    char line[512];
    line[0] = 0;
    while ((e = readdir(d)) != NULL) {
        total++;
        if (strstr(e->d_name, "ham") || strstr(e->d_name, "aps") || strstr(e->d_name, "slog") || strstr(e->d_name, "trace") || strstr(e->d_name, "mem")) {
            if (strlen(line) + strlen(e->d_name) + 2 < sizeof(line)) { strcat(line, e->d_name); strcat(line, " "); }
            n++;
        }
    }
    closedir(d);
    INFO("%s: %d entries, %d match ham|aps|slog|trace|mem: %s", dir, total, n, n ? line : "(none)");
}

static void probe_listing(void) {
    printf("[P4] image listing\n");
    list_matches("/proc/boot");
    list_matches("/system/bin");
    list_matches("/usr/bin");
    list_matches("/usr/sbin");
    list_matches("/system/lib");
    list_matches("/usr/lib");
}

static void probe_mutex_protocol(void) {
    printf("[P5] mutex protocol (priority inheritance of the server's state lock)\n");
    pthread_mutexattr_t def, pi;
    int proto_def = -1, proto_pi = -1;
    CHECK(pthread_mutexattr_init(&def) == 0 && pthread_mutexattr_getprotocol(&def, &proto_def) == 0, "the default protocol of a mutex attribute can be read");
    INFO("default protocol: %d (PTHREAD_PRIO_NONE %d, PTHREAD_PRIO_INHERIT %d, PTHREAD_PRIO_PROTECT %d)", proto_def, (int)PTHREAD_PRIO_NONE, (int)PTHREAD_PRIO_INHERIT, (int)PTHREAD_PRIO_PROTECT);
    int rc = pthread_mutexattr_init(&pi);
    if (rc == 0) rc = pthread_mutexattr_setprotocol(&pi, PTHREAD_PRIO_INHERIT);
    if (rc == 0) rc = pthread_mutexattr_getprotocol(&pi, &proto_pi);
    CHECK(rc == 0 && proto_pi == PTHREAD_PRIO_INHERIT, "PTHREAD_PRIO_INHERIT can be set and is read back");
    pthread_mutex_t m;
    CHECK(pthread_mutex_init(&m, &pi) == 0 && pthread_mutex_lock(&m) == 0 && pthread_mutex_unlock(&m) == 0 && pthread_mutex_destroy(&m) == 0,
          "a mutex created with that attribute locks, unlocks and is destroyed");
    pthread_mutexattr_destroy(&def);
    pthread_mutexattr_destroy(&pi);
}

int main(void) {
    printf("[*] QNX image probe: slog2, HAM, APS, typed memory, mutex protocol\n");
    probe_slog2();
    probe_ham_aps();
    probe_typed();
    probe_listing();
    probe_mutex_protocol();
    printf("[*] checks failed: %d, skipped: %d\n", g_failures, g_skips);
    printf("%s\n", g_failures == 0 ? "[+] QNX image probe finished." : "[-] QNX image probe FAILED.");
    return g_failures == 0 ? 0 : 1;
}

#else

int main(void) {
    printf("[SKIP] test_qnx_probe needs QNX Neutrino; nothing to do on this host.\n");
    return 0;
}

#endif
