/* Minimal template: connect OpenPayKernel to YOUR reader hardware.
 *
 * The kernel needs exactly one hardware function:
 *
 *     int transmit(void *ctx, const uint8_t *capdu, size_t clen, uint8_t *rapdu, size_t *rlen);
 *
 *   - capdu/clen : the command APDU, already complete (CLA INS P1 P2 [Lc data] [Le])
 *   - rapdu/rlen : on entry *rlen is the buffer size; on return the response data + SW1 SW2
 *   - return 0 on success, <0 on a Level-1 error (no card, card removed, timeout, CRC error)
 *
 * GET RESPONSE (61xx), wrong Le (6Cxx), TLV parsing and everything above are done by the
 * kernel. Card activation (contact power-up / contactless polling and anticollision) is
 * the reader's job and must happen before opk_*_process() is called.
 *
 * Replace vendor_sdk_exchange() below with your SDK call, build, and run.
 * STUDY USE ONLY - see the Disclaimer in README.md.
 * SPDX-License-Identifier: Apache-2.0 */
#include "example_common.h"

/* ---------------------------------------------------------------- your hardware goes here */
typedef struct {
    int device_handle; /* e.g. a serial port fd, a USB handle, an NFC controller context */
} my_device;

/* Stand-in for your vendor SDK. It answers "file not found" (6A82) to everything, so this
 * template runs without hardware and shows how the kernel reports the result. */
static int vendor_sdk_exchange(int handle, const uint8_t *cmd, size_t cmd_len, uint8_t *resp, size_t *resp_len)
{
    (void)handle; (void)cmd; (void)cmd_len;
    resp[0] = 0x6A;
    resp[1] = 0x82;
    *resp_len = 2;
    return 0;
}

static int my_transmit(void *ctx, const uint8_t *capdu, size_t clen, uint8_t *rapdu, size_t *rlen)
{
    my_device *dev = ctx;
    size_t n = *rlen;
    if (vendor_sdk_exchange(dev->device_handle, capdu, clen, rapdu, &n) != 0)
        return -1; /* Level-1 error: the kernel turns this into TRY AGAIN / END APPLICATION */
    if (n < 2)
        return -1; /* a valid response always ends with SW1 SW2 */
    *rlen = n;
    return 0;
}
/* ----------------------------------------------------------------------------------------- */

static int choose_app(void *ctx, const opk_app_candidate *c, int n) { (void)ctx; (void)c; (void)n; return 0; }
static int enter_pin(void *ctx, int online, int tries, char *pin) { (void)ctx; (void)online; (void)tries; (void)pin; return 0; }
static int go_online(void *ctx, const opk_db *db, opk_online_response *r) { (void)ctx; (void)db; (void)r; return 0; }

int main(int argc, char **argv)
{
    static opk_env env;
    static opk_db db;
    opk_transaction txn;
    opk_outcome out;
    int contact = argc > 1 && !strcmp(argv[1], "contact");

    my_device dev = {0};
    opk_reader hw = {my_transmit, &dev};
    tracing_reader trace = {hw};
    opk_reader reader = {tracing_transmit, &trace};

    example_env(&env);
    example_transaction(&txn, 100); /* 1.00 */
    printf("%s transaction, APDU trace:\n", contact ? "contact" : "contactless");
    if (contact) {
        opk_contact_host host = {choose_app, enter_pin, go_online, NULL};
        opk_contact_process(&env, &txn, &reader, &host, &out, &db);
    } else {
        opk_contactless_process(&env, &txn, &reader, &out, &db);
    }
    example_print_outcome(&out, &db);
    return 0;
}
