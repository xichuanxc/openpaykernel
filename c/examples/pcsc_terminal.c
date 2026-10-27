/* Run one transaction on a real PC/SC reader (contact or contactless).
 *
 *   build:  cmake -S . -B build -DOPK_BUILD_PCSC_EXAMPLE=ON && cmake --build build
 *           (macOS: PCSC.framework; Linux: libpcsclite-dev; Windows: winscard.lib)
 *   run:    ./build/opk_pcsc_terminal [contact] [amount_in_minor_units] [reader_index]
 *
 * The only PC/SC-specific code is pcsc_transmit(). Everything else is the portable kernel.
 * STUDY USE ONLY: use EMV test cards. A live card's PIN try counter and ATC are real.
 * See the Disclaimer in README.md.
 * SPDX-License-Identifier: Apache-2.0 */
#include "example_common.h"

#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

typedef struct {
    SCARDCONTEXT context;
    SCARDHANDLE card;
    DWORD protocol;
} pcsc_device;

/* ---------------------------------------------------------------- the hardware adapter */
static int pcsc_transmit(void *ctx, const uint8_t *capdu, size_t clen, uint8_t *rapdu, size_t *rlen)
{
    pcsc_device *d = ctx;
    const SCARD_IO_REQUEST *pci = d->protocol == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1;
    DWORD n = (DWORD)*rlen;
    LONG rc = SCardTransmit(d->card, pci, capdu, (DWORD)clen, NULL, rapdu, &n);
    if (rc != SCARD_S_SUCCESS || n < 2)
        return -1; /* card removed / communication error: Level-1 error */
    *rlen = n;
    return 0;
}
/* --------------------------------------------------------------------------------------- */

static int pcsc_open(pcsc_device *d, int index)
{
    char readers[2048];
    DWORD len = sizeof readers;
    if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &d->context) != SCARD_S_SUCCESS ||
        SCardListReaders(d->context, NULL, readers, &len) != SCARD_S_SUCCESS) {
        fprintf(stderr, "no PC/SC readers (is pcscd running?)\n");
        return -1;
    }
    const char *name = readers;
    for (int i = 0; i < index && *name; i++)
        name += strlen(name) + 1;
    if (!*name) {
        fprintf(stderr, "reader index %d not found\n", index);
        return -1;
    }
    printf("reader: %s\n", name);
    if (SCardConnect(d->context, name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &d->card,
                     &d->protocol) != SCARD_S_SUCCESS) {
        fprintf(stderr, "no card present\n");
        return -1;
    }
    return 0;
}

static void pcsc_close(pcsc_device *d)
{
    SCardDisconnect(d->card, SCARD_LEAVE_CARD);
    SCardReleaseContext(d->context);
}

/* ---- console host callbacks (study use: the PIN is typed in clear and not protected) */
static int choose_app(void *ctx, const opk_app_candidate *c, int n)
{
    char line[16];
    (void)ctx;
    for (int i = 0; i < n; i++)
        printf("  [%d] %s\n", i, c[i].label);
    printf("select application [0]: ");
    if (!fgets(line, sizeof line, stdin))
        return 0;
    return atoi(line);
}

static int enter_pin(void *ctx, int online, int tries, char *pin)
{
    char line[32];
    (void)ctx;
    printf("enter %s PIN (tries left %d), empty to bypass: ", online ? "online" : "offline", tries);
    if (!fgets(line, sizeof line, stdin))
        return 0;
    line[strcspn(line, "\r\n")] = 0;
    if (!line[0] || strlen(line) > 12)
        return 0;
    strcpy(pin, line);
    return 1;
}

static int go_online(void *ctx, const opk_db *db, opk_online_response *rsp)
{
    char line[8];
    (void)ctx; (void)db;
    printf("simulate issuer response: [a]pprove / [d]ecline / [u]nable to go online: ");
    if (!fgets(line, sizeof line, stdin) || line[0] == 'u')
        return 0;
    memset(rsp, 0, sizeof *rsp);
    rsp->approved = line[0] == 'a';
    memcpy(rsp->arc, rsp->approved ? "00" : "05", 2);
    return 1;
}

int main(int argc, char **argv)
{
    static opk_env env;
    static opk_db db;
    opk_transaction txn;
    opk_outcome out;
    int argi = 1, contact = 0;
    if (argi < argc && !strcmp(argv[argi], "contact")) {
        contact = 1;
        argi++;
    }
    uint32_t amount = argi < argc ? (uint32_t)atol(argv[argi++]) : 100;
    int index = argi < argc ? atoi(argv[argi]) : 0;

    pcsc_device dev;
    if (pcsc_open(&dev, index))
        return 1;
    opk_reader hw = {pcsc_transmit, &dev};
    tracing_reader trace = {hw};
    opk_reader reader = {tracing_transmit, &trace};

    example_env(&env);
    example_transaction(&txn, amount);
    printf("APDU trace:\n");
    if (contact) {
        opk_contact_host host = {choose_app, enter_pin, go_online, NULL};
        opk_contact_process(&env, &txn, &reader, &host, &out, &db);
    } else {
        opk_contactless_process(&env, &txn, &reader, &out, &db);
    }
    example_print_outcome(&out, &db);
    pcsc_close(&dev);
    return 0;
}
