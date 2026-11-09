#ifndef __APPLE__
#define _POSIX_C_SOURCE 200809L
#endif

#include "rdsetup_usb.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Requests are one operation byte plus a 32-byte per-boot token.
 * Replies are magic, state, and two big-endian uint32 lengths (log, ticket).
 * A ticket body includes its 96-byte Preboot directory and 48-byte digest first.
 * G reads state or results. S starts the single operation from the idle state.
 */
/* The ramdisk builder checks this marker before enabling USB mode. */
static const unsigned char magic[] __attribute__((used)) = "DRA1USB1";

static int read_all(int fd, unsigned char *data, size_t size) {
    while (size) {
        ssize_t n = recv(fd, data, size, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        data += n;
        size -= (size_t)n;
    }
    return 0;
}

static int write_all(int fd, const void *buffer, size_t size) {
    const unsigned char *data = buffer;
    while (size) {
#ifdef MSG_NOSIGNAL
        ssize_t n = send(fd, data, size, MSG_NOSIGNAL);
#else
        ssize_t n = send(fd, data, size, 0);
#endif
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        data += n;
        size -= (size_t)n;
    }
    return 0;
}

static int request(int fd, const unsigned char token[RDUSB_TOKEN_SIZE]) {
    struct timeval timeout = {2, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout)) return -1;
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one)) return -1;
#endif
    unsigned char data[1 + RDUSB_TOKEN_SIZE];
    if (read_all(fd, data, sizeof data)) return -1;
    unsigned diff = 0;
    for (size_t i = 0; i < RDUSB_TOKEN_SIZE; i++) diff |= data[i + 1] ^ token[i];
    return diff ? -1 : data[0];
}

static int reply(int fd, unsigned char state, const struct rdusb_report *report) {
    size_t log_size = report ? report->log_size : 0;
    size_t ticket_size = state == 'O' && report ? report->ticket_size : 0;
    if (log_size > RDUSB_MAX_LOG || ticket_size > RDUSB_MAX_TICKET) return -1;
    unsigned char header[17];
    memcpy(header, magic, sizeof magic - 1);
    header[8] = state;
    uint32_t lengths[] = {htonl((uint32_t)log_size), htonl((uint32_t)ticket_size)};
    memcpy(header + 9, lengths, sizeof lengths);
    if (write_all(fd, header, sizeof header)) return -1;
    if (log_size && write_all(fd, report->log, log_size)) return -1;
    if (ticket_size &&
        (write_all(fd, report->ticket_dir, RDUSB_DIR_SIZE) ||
         write_all(fd, report->ticket_digest, RDUSB_DIGEST_SIZE) ||
         write_all(fd, report->ticket, ticket_size))) return -1;
    return 0;
}

int rdusb_open(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {0};
#ifdef __APPLE__
    addr.sin_len = sizeof addr;
#endif
    addr.sin_family = AF_INET;
    addr.sin_port = htons(RDUSB_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) ||
        bind(fd, (struct sockaddr *)&addr, sizeof addr) || listen(fd, 4)) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

static int64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int rdusb_wait_start(int listener, const unsigned char token[RDUSB_TOKEN_SIZE], int timeout) {
    int64_t now = monotonic_ms();
    if (now < 0) return -1;
    int64_t deadline = now + (int64_t)timeout * 1000;
    struct pollfd pfd = {listener, POLLIN, 0};
    while ((now = monotonic_ms()) >= 0 && now < deadline) {
        int ready = poll(&pfd, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || !(pfd.revents & POLLIN)) return -1;
        int fd = accept(listener, NULL, NULL);
        if (fd < 0 && errno == EINTR) continue;
        if (fd < 0) return -1;
        int op = request(fd, token);
        if (op == 'G') reply(fd, 'R', NULL);
        int started = op == 'S' && reply(fd, 'S', NULL) == 0;
        close(fd);
        if (started) return 0;
    }
    return -1;
}

void rdusb_serve_result(int listener, const unsigned char token[RDUSB_TOKEN_SIZE], int ok,
                        const struct rdusb_report *report) {
    for (;;) {
        int fd = accept(listener, NULL, NULL);
        if (fd < 0 && errno == EINTR) continue;
        if (fd < 0) return;
        if (request(fd, token) == 'G') reply(fd, ok ? 'O' : 'E', report);
        close(fd);
    }
}
