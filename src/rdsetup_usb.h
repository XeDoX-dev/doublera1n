#ifndef RDSETUP_USB_H
#define RDSETUP_USB_H

#include <stddef.h>

#define RDUSB_PORT 42420
#define RDUSB_TOKEN_SIZE 32
#define RDUSB_MAX_LOG (64 * 1024)
#define RDUSB_MAX_TICKET (64 * 1024)
#define RDUSB_DIR_SIZE 96
#define RDUSB_DIGEST_SIZE 48

struct rdusb_report {
    const char *log;
    size_t log_size;
    const unsigned char *ticket;
    size_t ticket_size;
    const char *ticket_dir;
    const unsigned char *ticket_digest;
};

int rdusb_open(void);
int rdusb_wait_start(int listener, const unsigned char token[RDUSB_TOKEN_SIZE], int timeout);
void rdusb_serve_result(int listener, const unsigned char token[RDUSB_TOKEN_SIZE], int ok,
                        const struct rdusb_report *report);

#endif
