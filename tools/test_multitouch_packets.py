#!/usr/bin/env python3
"""Exercise the production Zephyr 1 and Zephyr 2 SPI parsers without a VM.

This compiles the actual parser source and actual packet/state declarations with
small stand-ins for QEMU object and endian helpers. It tests packet bytes and
state transitions, not controller firmware execution, SPI timing, or touch UI.
"""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
QEMU = ROOT / "vendor/qemu"

PRELUDE = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
typedef struct { unsigned unused; } SSIPeripheral;
typedef void QEMUTimer;
typedef void IPodTouchSYSICState;
typedef void IPodTouchGPIOState;
#define IPOD_TOUCH_MULTITOUCH(dev) ((IPodTouchMultitouchState *)(dev))
static void stw_be_p(void *p, uint16_t v) {
    uint8_t *b = p; b[0] = v >> 8; b[1] = v;
}
static void stl_le_p(void *p, uint32_t v) {
    uint8_t *b = p; for (unsigned i = 0; i < 4; i++) b[i] = v >> (i * 8);
}
static uint16_t lduw_be_p(const void *p) {
    const uint8_t *b = p; return (b[0] << 8) | b[1];
}
static uint32_t ldl_be_p(const void *p) {
    const uint8_t *b = p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | b[3];
}
static void hw_error(const char *format, ...) {
    va_list ap; va_start(ap, format); vfprintf(stderr, format, ap);
    va_end(ap); fputc('\n', stderr); exit(2);
}
"""

TESTS = r"""
static unsigned checks;
#define CHECK(v) do { assert(v); checks++; } while (0)
static void xfer(IPodTouchMultitouchState *s, const uint8_t *tx,
                 uint8_t *rx, unsigned length) {
    for (unsigned i = 0; i < length; i++) {
        rx[i] = ipod_touch_multitouch_transfer((SSIPeripheral *)s, tx[i]);
    }
    ipod_touch_multitouch_end_transfer(s);
    CHECK(s->z1_index == 0);
}
static uint16_t sum(const uint8_t *bytes, unsigned length) {
    uint16_t total = 0;
    for (unsigned i = 0; i < length; i++) total += bytes[i];
    return total;
}
static uint16_t upload(IPodTouchMultitouchState *s, uint32_t address,
                       bool bad_checksum) {
    uint8_t tx[MT_Z1_PACKET_SIZE] = {0xc2}, rx[MT_Z1_PACKET_SIZE];
    tx[1] = address >> 24; tx[2] = address >> 16;
    tx[3] = address >> 8; tx[4] = address;
    for (unsigned i = 6; i < sizeof(tx) - 2; i++) tx[i] = i * 13;
    uint16_t checksum = sum(tx, sizeof(tx) - 2);
    stw_be_p(tx + sizeof(tx) - 2, checksum + bad_checksum);
    xfer(s, tx, rx, sizeof(tx));
    CHECK(!s->z1_running);
    CHECK(s->z1_upload_checksum == checksum);
    if (s->z1_upload_valid) {
        CHECK(!memcmp(s->z1_firmware + address - 0x40000000,
                      tx + 6, sizeof(tx) - 8));
    }
    return checksum;
}
static void verify(IPodTouchMultitouchState *s, uint16_t checksum,
                   bool valid) {
    const uint8_t tx[] = {5, 0, 0, 6}; uint8_t rx[4];
    xfer(s, tx, rx, sizeof(tx));
    CHECK(rx[0] == 0xd0);
    CHECK(rx[1] == !valid);
    CHECK(lduw_be_p(rx + 2) == checksum);
}
static void execute(IPodTouchMultitouchState *s, bool valid) {
    const uint8_t tx[] = {0xc4, 0, 0, 0xc4}; uint8_t rx[4];
    xfer(s, tx, rx, sizeof(tx)); CHECK(s->z1_running == valid);
}
static void report(IPodTouchMultitouchState *s, uint8_t id,
                   const uint8_t *data, unsigned length) {
    uint8_t tx[MT_Z1_PACKET_SIZE], rx[MT_Z1_PACKET_SIZE];
    memset(tx, 0x8f, 8); tx[1] = id; xfer(s, tx, rx, 8);
    CHECK(rx[0] == 0xaa && rx[1] == id);
    CHECK(lduw_be_p(rx + 4) == length);
    CHECK(lduw_be_p(rx + 6) == id + sum(rx + 4, 2));
    memset(tx, 0x82, length + 6); tx[1] = id;
    xfer(s, tx, rx, length + 6);
    CHECK(rx[0] == 0xaa && rx[1] == id);
    CHECK(!memcmp(rx + 4, data, length));
    CHECK(lduw_be_p(rx + length + 4) == id + sum(data, length));
}
static void frame(IPodTouchMultitouchState *s, uint8_t length_cmd,
                  uint8_t data_cmd) {
    uint8_t tx[MT_Z1_PACKET_SIZE], rx[MT_Z1_PACKET_SIZE];
    memset(tx, length_cmd, 8); xfer(s, tx, rx, 8);
    unsigned offset = length_cmd == 0x46 ? 1 : 4;
    unsigned length = sizeof(MTFrameHeader) + sizeof(FingerData) + 2;
    CHECK(rx[0] == 0xaa && lduw_be_p(rx + offset) == length);
    CHECK(lduw_be_p(rx + offset + 2) == sum(rx + offset, 2));
    MTFrame expected = *s->next_frame;
    memset(tx, data_cmd, length + 1); xfer(s, tx, rx, length + 1);
    CHECK(rx[0] == 0xaa);
    CHECK(!memcmp(rx + 1, &expected.frame_packet.header, sizeof(MTFrameHeader)));
    CHECK(!memcmp(rx + 1 + sizeof(MTFrameHeader), &expected.finger_data,
                  sizeof(FingerData)));
    CHECK(lduw_be_p(rx + length - 1) == sum(rx + 1, length - 2));
    CHECK(s->next_frame == NULL);
}
int main(int argc, char **argv) {
    IPodTouchMultitouchState *s = calloc(1, sizeof(*s));
    assert(s); s->zephyr1 = true;
    if (argc > 1) {
        s->z1_running = true;
        if (!strcmp(argv[1], "unknown-command")) {
            ipod_touch_multitouch_transfer((SSIPeripheral *)s, 0xfe);
        } else if (!strcmp(argv[1], "unsupported-write")) {
            const uint8_t tx[] = {0x92, MT_REPORT_FAMILY_ID}; uint8_t rx[2];
            xfer(s, tx, rx, sizeof(tx));
        } else if (!strcmp(argv[1], "truncated-upload")) {
            const uint8_t tx[] = {0xc2, 0x40, 0, 0}; uint8_t rx[4];
            xfer(s, tx, rx, sizeof(tx));
        } else if (!strcmp(argv[1], "oversized-main")) {
            const uint8_t tx[] = {0xc2, 0, 0, 0}; uint8_t rx[4];
            xfer(s, tx, rx, sizeof(tx));
            for (unsigned i = 0; i <= MT_Z1_FIRMWARE_RAM_SIZE; i++) {
                ipod_touch_multitouch_transfer((SSIPeripheral *)s, 0);
            }
        }
        return 1;
    }
    execute(s, false);
    uint16_t checksum = upload(s, 0x40001000, false);
    CHECK(s->z1_upload_valid); verify(s, checksum, true);
    execute(s, true); verify(s, checksum, true); CHECK(s->z1_running);
    uint8_t original = s->z1_firmware[0x1000];
    checksum = upload(s, 0x40001000, true);
    CHECK(!s->z1_upload_valid); verify(s, checksum, false);
    CHECK(s->z1_firmware[0x1000] == original); execute(s, false);
    checksum = upload(s, 0x3fffffff, false);
    CHECK(!s->z1_upload_valid); verify(s, checksum, false);
    checksum = upload(s, 0x40010000 - 0x3f8, false);
    CHECK(s->z1_upload_valid); verify(s, checksum, true);
    checksum = upload(s, 0x40010000 - 0x3f8 + 1, false);
    CHECK(!s->z1_upload_valid); verify(s, checksum, false);
    checksum = upload(s, 0x40000000, false); execute(s, true);
    const uint8_t blank[] = {0xc2, 0, 0, 0};
    uint8_t main_firmware[2059], main_rx[2059];
    xfer(s, blank, main_rx, sizeof(blank));
    CHECK(s->z1_main_upload && !s->z1_upload_valid && !s->z1_running);
    for (unsigned i = 0; i < sizeof(main_firmware); i++) {
        main_firmware[i] = i * 7 + 5;
    }
    main_firmware[0] = 0xfe; main_firmware[1] = 0xc4;
    main_firmware[2] = 0xc2; main_firmware[3] = 5;
    xfer(s, main_firmware, main_rx, sizeof(main_firmware));
    CHECK(!s->z1_main_upload && s->z1_upload_valid);
    CHECK(s->z1_main_length == sizeof(main_firmware));
    CHECK(!memcmp(s->z1_main_firmware, main_firmware, sizeof(main_firmware)));
    checksum = sum(main_firmware, sizeof(main_firmware));
    verify(s, checksum, true); execute(s, true);
    const uint8_t interface_tx[] = {0xd0, 0xd0, 0xd0, 0xd0};
    uint8_t rx[MT_Z1_PACKET_SIZE], tx[MT_Z1_PACKET_SIZE];
    xfer(s, interface_tx, rx, 4);
    CHECK(rx[0] == 0xaa && rx[1] == MT_INTERFACE_VERSION);
    CHECK(lduw_be_p(rx + 2) == MT_MAX_PACKET_SIZE);
    const uint8_t family[] = {MT_FAMILY_ID};
    const uint8_t sensor[] = {MT_ENDIANNESS, MT_SENSOR_ROWS, MT_SENSOR_COLUMNS,
                              MT_BCD_VERSION >> 8, MT_BCD_VERSION & 255};
    const uint8_t region[] = {0};
    uint8_t dimensions[8];
    stl_le_p(dimensions, MT_SENSOR_SURFACE_WIDTH);
    stl_le_p(dimensions + 4, MT_SENSOR_SURFACE_HEIGHT);
    report(s, MT_REPORT_FAMILY_ID, family, sizeof(family));
    report(s, MT_REPORT_SENSOR_INFO, sensor, sizeof(sensor));
    report(s, MT_REPORT_SENSOR_REGION_DESC, region, sizeof(region));
    report(s, MT_REPORT_SENSOR_REGION_PARAM, region, sizeof(region));
    report(s, MT_REPORT_SENSOR_DIMENSIONS, dimensions, sizeof(dimensions));
    memset(tx, 0x8f, 8); tx[1] = 0xfe; xfer(s, tx, rx, 8);
    CHECK(rx[4] == 0x10 && rx[5] == 0);
    CHECK(lduw_be_p(rx + 6) == 0xfe + 0x10);
    memset(tx, 0x92, 7); tx[1] = MT_REPORT_UNKNOWN1; tx[4] = 3;
    stw_be_p(tx + 5, MT_REPORT_UNKNOWN1 + 3); xfer(s, tx, rx, 7);
    CHECK(lduw_be_p(rx + 5) == MT_REPORT_UNKNOWN1 + 3);
    CHECK(s->z1_report70 == 3);
    const uint8_t written[] = {3}; report(s, MT_REPORT_UNKNOWN1, written, 1);
    tx[4] = 7; stw_be_p(tx + 5, 1); xfer(s, tx, rx, 7);
    CHECK(s->z1_report70 == 3);
    for (unsigned cmd = 0; cmd < 3; cmd++) {
        memset(tx, cmd ? 0x64 + cmd - 1 : 0x46, 8); xfer(s, tx, rx, 8);
        CHECK(lduw_be_p(rx + (cmd ? 4 : 1)) == 0);
        s->next_frame = calloc(1, sizeof(MTFrame)); assert(s->next_frame);
        s->next_frame->frame_packet.header.type = MT_FRAME_TYPE_PATH;
        s->next_frame->frame_packet.header.headerLen = sizeof(MTFrameHeader);
        s->next_frame->frame_packet.header.numFingers = 1;
        s->next_frame->frame_packet.header.fingerDataLen = sizeof(FingerData);
        s->next_frame->finger_data.id = 1;
        s->next_frame->finger_data.event = MT_EVENT_TOUCH_START;
        s->next_frame->finger_data.x = 0x1234;
        frame(s, cmd ? 0x64 + cmd - 1 : 0x46, cmd ? 0x68 : 0x47);
    }
    memset(tx, 0x68, 3); xfer(s, tx, rx, 3);
    CHECK(rx[0] == 0xaa && rx[1] == 0 && rx[2] == 0);
    free(s);
    s = calloc(1, sizeof(*s)); assert(s);
    memset(tx, 0, 16); tx[0] = MT_CMD_GET_CMD_STATUS;
    tx[1] = 0xc2; tx[2] = 0xc4; tx[3] = 5; xfer(s, tx, rx, 16);
    CHECK(!s->zephyr1 && !s->cur_cmd);
    CHECK(rx[0] == MT_CMD_GET_CMD_STATUS);
    CHECK(rx[14] == MT_CMD_GET_CMD_STATUS && rx[15] == 0);
    free(s->out_buffer); free(s->in_buffer); free(s);
    printf("%u packet and state assertions passed\n", checks);
    return 0;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    compiler = shutil.which("clang") or shutil.which("cc")
    if not compiler:
        raise SystemExit("No local C compiler available")
    header = (QEMU / "include/hw/arm/ipod_touch_multitouch.h").read_text()
    declarations = header[header.index("#define MT_INTERFACE_VERSION"):
                          header.index("void ipod_touch_multitouch_on_touch")]
    source = (QEMU / "hw/arm/ipod_touch_multitouch.c").read_text()
    parsers = source[source.index("static unsigned z1_report_size"):
                     source.index("static MTFrame *get_frame")]
    with tempfile.TemporaryDirectory(prefix="iphoneos1-multitouch-test-") as tmp:
        tmp = Path(tmp)
        program = tmp / "packets.c"
        binary = tmp / "packets"
        program.write_text(PRELUDE + declarations + parsers + TESTS)
        subprocess.run([compiler, "-std=c11", "-O1", "-g",
                        "-fsanitize=address,undefined", str(program), "-o", str(binary)],
                       check=True, timeout=30, capture_output=True, text=True)
        positive = subprocess.run([str(binary)], check=True, timeout=10,
                                  capture_output=True, text=True)
        rejected = []
        for mode in ("unknown-command", "unsupported-write", "truncated-upload",
                     "oversized-main"):
            result = subprocess.run([str(binary), mode], timeout=10,
                                    capture_output=True, text=True)
            if result.returncode != 2 or "Zephyr 1:" not in result.stderr:
                raise AssertionError(f"{mode} was not explicitly rejected: {result}")
            rejected.append({"case": mode, "exit_code": result.returncode,
                             "diagnostic": result.stderr.strip()})
    report = {"production_source": str(QEMU / "hw/arm/ipod_touch_multitouch.c"),
              "compiler": compiler, "sanitizers": ["address", "undefined"],
              "result": positive.stdout.strip(), "rejected_cases": rejected,
              "validation_boundary": "Production SPI parser packet bytes and state only; "
              "no firmware execution, MMIO/CS/IRQ wiring or timing, or touch UI check"}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
