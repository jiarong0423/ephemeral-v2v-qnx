/*
 * v2v_iru_io.inc.c - G17 small POSIX helpers shared by the three G17 programs (sentinel, host stand-in, cloud simulation):
 * "FD or PATH" channel arguments, exact-size message reads, length-prefixed radio messages, open-descriptor listing.
 * Code is shared; state is not (each program is its own process with its own copy).
 */
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

/* "7" -> descriptor 7; anything else -> open the path (FIFOs on the QNX target are opened O_RDWR so that open() does not wait
 * for the other side; O_RDWR on a FIFO works on QNX and Linux, POSIX leaves it undefined) */
static int iru_chan_open(const char *arg, int write_side) {
    if (arg == NULL || *arg == '\0') return -1;
    const char *p = arg;
    while (*p >= '0' && *p <= '9') p++;
    if (*p == '\0') return atoi(arg);
    struct stat st;
    int fifo = stat(arg, &st) == 0 && S_ISFIFO(st.st_mode);
    return open(arg, fifo ? O_RDWR : (write_side ? (O_WRONLY | O_CREAT | O_APPEND) : O_RDONLY), 0600);
}
static int iru_write_all(int fd, const void *b, size_t n) {
    const uint8_t *p = (const uint8_t *)b;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}
/* accumulating reader for fixed-size or length-prefixed messages */
typedef struct { uint8_t b[1024]; size_t n; int eof; } iru_rbuf_t;
static int iru_rbuf_fill(int fd, iru_rbuf_t *r) {
    if (r->eof || r->n >= sizeof(r->b)) return 0;
    ssize_t k = read(fd, r->b + r->n, sizeof(r->b) - r->n);
    if (k == 0) { r->eof = 1; return 0; }
    if (k < 0) return errno == EINTR || errno == EAGAIN ? 0 : -1;
    r->n += (size_t)k;
    return (int)k;
}
static int iru_rbuf_take(iru_rbuf_t *r, void *out, size_t n) {
    if (r->n < n) return 0;
    memcpy(out, r->b, n);
    memmove(r->b, r->b + n, r->n - n);
    r->n -= n;
    return 1;
}
/* radio messages: 2-byte little-endian length + payload (up to 300 bytes) */
static int iru_rbuf_take_lp(iru_rbuf_t *r, uint8_t *out, size_t *len) {
    if (r->n < 2) return 0;
    size_t l = (size_t)r->b[0] | ((size_t)r->b[1] << 8);
    if (l > 300) { r->n = 0; return 0; }                    /* resynchronise on garbage */
    if (r->n < 2 + l) return 0;
    memcpy(out, r->b + 2, l);
    memmove(r->b, r->b + 2 + l, r->n - 2 - l);
    r->n -= 2 + l;
    *len = l;
    return 1;
}
/* prints the open descriptors 0..255 of this process (isolation evidence) */
/* each as N:T, T = p pipe/FIFO, s socket, c character device, f regular file, d directory, ? other */
static void iru_print_fds(const char *tag) {
    printf("%s fds:", tag);
    for (int fd = 0; fd < 256; ++fd) {
        if (fcntl(fd, F_GETFD) == -1) continue;
        struct stat st;
        char t = '?';
        if (fstat(fd, &st) == 0) t = S_ISFIFO(st.st_mode) ? 'p' : S_ISSOCK(st.st_mode) ? 's' : S_ISCHR(st.st_mode) ? 'c' : S_ISREG(st.st_mode) ? 'f' : S_ISDIR(st.st_mode) ? 'd' : '?';
        printf(" %d:%c", fd, t);
    }
    printf("\n");
}
static volatile sig_atomic_t g_iru_stop;
static volatile sig_atomic_t g_iru_usr1;
static volatile sig_atomic_t g_iru_usr2;
static void iru_on_term(int s) { (void)s; g_iru_stop = 1; }
static void iru_on_usr1(int s) { (void)s; g_iru_usr1 = 1; }
static void iru_on_usr2(int s) { (void)s; g_iru_usr2 = 1; }
static void iru_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = iru_on_term; sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = iru_on_usr1; sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = iru_on_usr2; sigaction(SIGUSR2, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}
