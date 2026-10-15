#!/usr/bin/env python3
"""Exercise actual production UART MMIO functions without launching a VM.

The C harness uses the declarations and function bodies from
hw/char/exynos4210_uart.c. Only QEMU infrastructure (clock, IRQ, chardev and
object types) is stubbed. Assertions cover original-kernel register sequences,
not UART wire timing, baud measurement, DMA, or a working baseband.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "vendor/qemu/hw/char/exynos4210_uart.c"

PRELUDE = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint64_t hwaddr;
typedef struct { unsigned unused; } SysBusDevice;
typedef struct { unsigned unused; } MemoryRegion;
typedef void DeviceState;
typedef enum { CHR_EVENT_BREAK = 1 } QEMUChrEvent;
typedef struct {
    bool connected;
    unsigned writes, accepted_inputs;
    uint8_t last_byte;
} CharBackend;
typedef struct { int speed, parity, data_bits, stop_bits; } QEMUSerialSetParams;
typedef struct { int level; unsigned transitions; } IRQStub;
typedef IRQStub *qemu_irq;
typedef struct {
    bool armed;
    uint64_t deadline;
    void (*callback)(void *);
    void *opaque;
} QEMUTimer;
#define OBJECT_DECLARE_SIMPLE_TYPE(T, N) typedef struct T T;
#define EXYNOS4210_UART(p) ((Exynos4210UartState *)(p))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define g_free free
#define g_malloc0(n) calloc(1, (n))
#define NANOSECONDS_PER_SECOND UINT64_C(1000000000)
#define QEMU_CLOCK_VIRTUAL 0
#define CHR_IOCTL_SERIAL_SET_PARAMS 1
static uint64_t fake_clock;
static uint64_t qemu_clock_get_ns(int clock) {
    assert(clock == QEMU_CLOCK_VIRTUAL); return fake_clock;
}
static void timer_mod(QEMUTimer *t, uint64_t deadline) {
    assert(t && deadline >= fake_clock);
    t->deadline = deadline; t->armed = true;
}
static void timer_del(QEMUTimer *t) { assert(t); t->armed = false; }
static void qemu_set_irq(qemu_irq irq, int level) {
    assert(irq && (level == 0 || level == 1));
    if (irq->level != level) irq->transitions++;
    irq->level = level;
}
static void qemu_irq_raise(qemu_irq irq) { qemu_set_irq(irq, 1); }
static void qemu_irq_lower(qemu_irq irq) { qemu_set_irq(irq, 0); }
static bool qemu_chr_fe_backend_connected(CharBackend *chr) {
    return chr->connected;
}
static int qemu_chr_fe_write_all(CharBackend *chr, const uint8_t *p, int n) {
    assert(chr->connected && n == 1); chr->writes++; chr->last_byte = *p;
    return n;
}
static void qemu_chr_fe_accept_input(CharBackend *chr) {
    chr->accepted_inputs++;
}
static int qemu_chr_fe_ioctl(CharBackend *chr, int command, void *params) {
    (void)chr; assert(command == CHR_IOCTL_SERIAL_SET_PARAMS);
    assert(((QEMUSerialSetParams *)params)->speed > 0); return 0;
}
"""

TESTS = r"""
static unsigned checks;
#define CHECK(v) do { \
    if (!(v)) { \
        fprintf(stderr, "check failed line %d: %s\n", __LINE__, #v); \
        abort(); \
    } \
    checks++; \
} while (0)
typedef struct {
    Exynos4210UartState state;
    IRQStub irq, dma;
    QEMUTimer timer;
} Fixture;
static void init(Fixture *f, bool legacy, bool connected) {
    memset(f, 0, sizeof(*f)); fake_clock = 0;
    f->state.s5l8900_legacy = legacy;
    f->state.channel = 1;
    f->state.rx.size = f->state.tx.size = 16;
    f->state.wordtime = UINT64_C(1000000);
    f->state.irq = &f->irq; f->state.dmairq = &f->dma;
    f->state.chr.connected = connected;
    f->state.fifo_timeout_timer = &f->timer;
    f->timer.callback = exynos4210_uart_timeout_int;
    f->timer.opaque = &f->state;
    exynos4210_uart_reset((DeviceState *)&f->state);
    CHECK(f->state.s5l8900_legacy == legacy);
    CHECK(f->state.reg[I_(UTRSTAT)] == 6);
}
static void done(Fixture *f) {
    free(f->state.rx.data); free(f->state.tx.data);
}
static void wr(Fixture *f, hwaddr offset, uint32_t value) {
    exynos4210_uart_write(&f->state, offset, value, 4);
}
static uint32_t rd(Fixture *f, hwaddr offset) {
    return exynos4210_uart_read(&f->state, offset, 4);
}
static void expire(Fixture *f) {
    CHECK(f->timer.armed);
    CHECK(f->timer.deadline >= fake_clock);
    fake_clock = f->timer.deadline;
    f->timer.armed = false;
    f->timer.callback(f->timer.opaque);
}
static void original_configuration(void) {
    Fixture f; init(&f, true, true);
    /* Captured UART1 configuration from the original 1A543a driver. */
    wr(&f, ULCON, 3); wr(&f, UCON, 0x15c85); wr(&f, UFCON, 0x61);
    wr(&f, UBRDIV, 0x9b); wr(&f, UINTSP, 0); wr(&f, UINTM, 0xc0000);
    CHECK(f.irq.level == 0);
    for (unsigned i = 0; i < 32; i++) {
        wr(&f, UTXH, i);
        exynos4210_uart_update_irq(&f.state);
        CHECK(f.irq.level == 0);
    }
    CHECK(f.state.chr.writes == 32);
    CHECK(rd(&f, UTRSTAT) == 0x26);
    CHECK(rd(&f, UINTP) == 0);
    CHECK(rd(&f, UINTSP) == 0);
    CHECK(rd(&f, UINTM) == 0xc0000);
    CHECK(f.irq.transitions == 0);
    wr(&f, UTRSTAT, 0x20);
    CHECK(rd(&f, UTRSTAT) == 6);
    CHECK(f.irq.level == 0);
    done(&f);
}
static void transmit_and_ack(bool connected) {
    Fixture f; init(&f, true, connected);
    wr(&f, UFCON, 1); wr(&f, UCON, 0); wr(&f, UCON, 0x2000);
    CHECK(f.irq.level == 1);
    CHECK(rd(&f, UTRSTAT) == 0x26);
    wr(&f, UTRSTAT, 0x20);
    CHECK(f.irq.level == 0);
    CHECK(rd(&f, UTRSTAT) == 6);
    unsigned transitions = f.irq.transitions;
    for (unsigned i = 0; i < 16; i++) {
        exynos4210_uart_update_irq(&f.state);
        CHECK(f.irq.level == 0);
        CHECK(rd(&f, UTRSTAT) == 6);
    }
    CHECK(f.irq.transitions == transitions);
    for (unsigned i = 0; i < 3; i++) {
        wr(&f, UTXH, 0x41 + i);
        CHECK(f.irq.level == 1);
        CHECK(rd(&f, UTRSTAT) == 0x26);
        CHECK(fifo_elements_number(&f.state.tx) == 0);
        wr(&f, UTRSTAT, 0x20);
        CHECK(f.irq.level == 0);
        CHECK(rd(&f, UTRSTAT) == 6);
    }
    CHECK(f.state.chr.writes == (connected ? 3 : 0));
    wr(&f, UTXH, 0x7f); wr(&f, UCON, 0);
    CHECK(f.irq.level == 0);
    CHECK(rd(&f, UTRSTAT) == 0x26);
    wr(&f, UCON, 0x2000);
    CHECK(f.irq.level == 1);
    wr(&f, UFCON, 5);
    CHECK(f.irq.level == 0);
    CHECK(rd(&f, UTRSTAT) == 6);
    done(&f);
}
static void cts_edges(void) {
    Fixture f; init(&f, true, true);
    wr(&f, UCON, 0x14005);
    exynos4210_uart_cts(&f.state, 0, 0);
    CHECK(rd(&f, UMSTAT) == 0); CHECK(f.irq.level == 0);
    exynos4210_uart_cts(&f.state, 0, 1);
    CHECK(rd(&f, UMSTAT) == 1); CHECK(rd(&f, UTRSTAT) == 0x46);
    CHECK(f.irq.level == 1);
    wr(&f, UTRSTAT, 0x40); CHECK(f.irq.level == 0);
    exynos4210_uart_cts(&f.state, 0, 1);
    CHECK(rd(&f, UTRSTAT) == 6); CHECK(f.irq.level == 0);
    exynos4210_uart_cts(&f.state, 0, 0);
    CHECK(rd(&f, UMSTAT) == 0); CHECK(f.irq.level == 1);
    wr(&f, UTRSTAT, 0x40); CHECK(f.irq.level == 0);
    CHECK(f.irq.transitions == 4);
    /* A physical change can latch while its interrupt is disabled. */
    wr(&f, UCON, 5); exynos4210_uart_cts(&f.state, 0, 1);
    CHECK(f.irq.level == 0); CHECK(rd(&f, UTRSTAT) == 0x46);
    wr(&f, UCON, 0x4005); CHECK(f.irq.level == 1);
    wr(&f, UTRSTAT, 0x40); CHECK(f.irq.level == 0);
    exynos4210_uart_reset((DeviceState *)&f.state);
    CHECK(rd(&f, UMSTAT) == 1); CHECK(f.irq.level == 0);
    done(&f);
}
static void receive_timeout_and_drain(void) {
    Fixture f; init(&f, true, true);
    wr(&f, UCON, 0x1885); wr(&f, UFCON, 1);
    const uint8_t bytes[] = {0x41, 0x42, 0x43};
    exynos4210_uart_receive(&f.state, bytes, 3);
    CHECK(rd(&f, UFSTAT) == 3);
    CHECK(rd(&f, UTRSTAT) == 0xf); CHECK(f.irq.level == 1);
    CHECK(f.timer.armed);
    wr(&f, UTRSTAT, 8);
    CHECK(f.irq.level == 0); CHECK(rd(&f, UTRSTAT) == 7);
    expire(&f);
    CHECK(f.irq.level == 1); CHECK(rd(&f, UTRSTAT) == 0x17);
    wr(&f, UTRSTAT, 0x10);
    CHECK(f.irq.level == 0); CHECK(rd(&f, UTRSTAT) == 7);
    for (unsigned i = 0; i < 3; i++) {
        CHECK(rd(&f, URXH) == bytes[i]);
        CHECK(rd(&f, UFSTAT) == 2 - i);
    }
    CHECK(rd(&f, UTRSTAT) == 6); CHECK(!f.timer.armed);
    CHECK(f.state.chr.accepted_inputs == 3);
    CHECK(f.irq.level == 0);
    exynos4210_uart_receive(&f.state, bytes, 1);
    CHECK(f.irq.level == 1);
    wr(&f, UTRSTAT, 7); /* Read-only readiness bits cannot be cleared. */
    CHECK(rd(&f, UTRSTAT) == 0xf);
    wr(&f, UFCON, 3);
    CHECK(rd(&f, UTRSTAT) == 6); CHECK(!f.timer.armed);
    CHECK(rd(&f, UFSTAT) == 0); CHECK(f.irq.level == 0);
    /* With FIFO disabled, URXH still clears data-ready on a read. */
    wr(&f, UFCON, 0);
    exynos4210_uart_receive(&f.state, bytes, 1);
    CHECK(rd(&f, URXH) == 0x41);
    wr(&f, UTRSTAT, 8);
    CHECK(rd(&f, UTRSTAT) == 6); CHECK(f.irq.level == 0);
    done(&f);
}
static void receive_full_drain_and_overrun(void) {
    Fixture f; init(&f, true, true);
    wr(&f, UCON, 0x1885); wr(&f, UFCON, 1);
    uint8_t bytes[20];
    for (unsigned i = 0; i < sizeof(bytes); i++) bytes[i] = 0x30 + i;
    CHECK(exynos4210_uart_can_receive(&f.state) == 16);
    exynos4210_uart_receive(&f.state, bytes, 16);
    CHECK(exynos4210_uart_rx_count(&f.state) == 16);
    CHECK(exynos4210_uart_can_receive(&f.state) == 0);
    CHECK(rd(&f, UFSTAT) == 0x100);
    CHECK(f.state.rx.sp == f.state.rx.rp);
    CHECK(f.irq.level == 1);
    wr(&f, UTRSTAT, 8); CHECK(f.irq.level == 0);
    /* Incoming data at capacity must not overwrite the first queued byte. */
    exynos4210_uart_receive(&f.state, bytes + 16, 1);
    CHECK(exynos4210_uart_rx_count(&f.state) == 16);
    CHECK(rd(&f, UERSTAT) == UERSTAT_OVERRUN);
    CHECK(rd(&f, UERSTAT) == 0);
    CHECK(rd(&f, UFSTAT) == 0x100);
    wr(&f, UTRSTAT, 8);
    CHECK(rd(&f, URXH) == bytes[0]);
    CHECK(rd(&f, UFSTAT) == 15);
    CHECK(exynos4210_uart_can_receive(&f.state) == 1);
    /* Refill one slot, wrapping the ring while its read pointer is nonzero. */
    exynos4210_uart_receive(&f.state, bytes + 16, 1);
    CHECK(rd(&f, UFSTAT) == 0x100);
    wr(&f, UTRSTAT, 8);
    for (unsigned i = 1; i <= 16; i++) {
        CHECK(rd(&f, URXH) == bytes[i]);
        CHECK(exynos4210_uart_rx_count(&f.state) == 16 - i);
    }
    CHECK(rd(&f, UFSTAT) == 0);
    CHECK(rd(&f, UTRSTAT) == 6); CHECK(!f.timer.armed);
    CHECK(exynos4210_uart_can_receive(&f.state) == 16);
    /* One oversized delivery admits only the available physical capacity. */
    exynos4210_uart_receive(&f.state, bytes, sizeof(bytes));
    CHECK(rd(&f, UERSTAT) == UERSTAT_OVERRUN);
    CHECK(rd(&f, UFSTAT) == 0x100);
    CHECK(exynos4210_uart_rx_count(&f.state) == 16);
    wr(&f, UTRSTAT, 8);
    for (unsigned i = 0; i < 16; i++) CHECK(rd(&f, URXH) == bytes[i]);
    CHECK(rd(&f, UFSTAT) == 0); CHECK(f.irq.level == 0);
    /* A BREAK at capacity also leaves the existing FIFO bytes intact. */
    exynos4210_uart_receive(&f.state, bytes, 16);
    exynos4210_uart_event(&f.state, CHR_EVENT_BREAK);
    CHECK(exynos4210_uart_rx_count(&f.state) == 16);
    CHECK(rd(&f, UERSTAT) == (UERSTAT_BREAK | UERSTAT_OVERRUN));
    wr(&f, UTRSTAT, 8);
    for (unsigned i = 0; i < 16; i++) CHECK(rd(&f, URXH) == bytes[i]);
    CHECK(rd(&f, UFSTAT) == 0); CHECK(f.irq.level == 0);
    exynos4210_uart_event(&f.state, CHR_EVENT_BREAK);
    CHECK(rd(&f, UERSTAT) == UERSTAT_BREAK);
    CHECK(rd(&f, UFSTAT) == 1);
    CHECK(rd(&f, URXH) == 0); wr(&f, UTRSTAT, 8);
    CHECK(rd(&f, UFSTAT) == 0); CHECK(f.irq.level == 0);
    /* Empty callbacks cannot synthesize a byte or interrupt. */
    exynos4210_uart_receive(&f.state, bytes, 0);
    CHECK(rd(&f, UFSTAT) == 0); CHECK(rd(&f, UTRSTAT) == 6);
    CHECK(f.irq.level == 0);
    done(&f);
    /* Production M68 allocates256 bytes; advertised capacity remains16. */
    init(&f, true, true);
    f.state.rx.size = 256;
    exynos4210_uart_reset((DeviceState *)&f.state);
    wr(&f, UCON, 0x1885); wr(&f, UFCON, 1);
    CHECK(exynos4210_uart_can_receive(&f.state) == 16);
    exynos4210_uart_receive(&f.state, bytes, sizeof(bytes));
    CHECK(rd(&f, UFSTAT) == 0x100);
    CHECK(exynos4210_uart_rx_count(&f.state) == 16);
    CHECK(exynos4210_uart_can_receive(&f.state) == 0);
    CHECK(rd(&f, UERSTAT) == UERSTAT_OVERRUN);
    wr(&f, UTRSTAT, 8);
    for (unsigned i = 0; i < 16; i++) CHECK(rd(&f, URXH) == bytes[i]);
    CHECK(rd(&f, UFSTAT) == 0); CHECK(rd(&f, UTRSTAT) == 6);
    CHECK(f.irq.level == 0);
    done(&f);
}
static void baud_register_storage(void) {
    Fixture f; init(&f, true, true);
    wr(&f, UCON, 0); wr(&f, UCON, 0x2000);
    const unsigned offsets[] = {0x30, 0x34, 0x38};
    for (unsigned i = 0; i < 3; i++) {
        wr(&f, offsets[i], 0xffffffff);
        CHECK(rd(&f, offsets[i]) == 0xffffffff);
        CHECK(rd(&f, UTRSTAT) == 0x26);
        CHECK(f.irq.level == 1);
    }
    wr(&f, UTRSTAT, 0x20); CHECK(f.irq.level == 0);
    for (unsigned i = 0; i < 3; i++) {
        wr(&f, offsets[i], 0x12340000 + i);
        CHECK(rd(&f, offsets[i]) == 0x12340000 + i);
        CHECK(rd(&f, UTRSTAT) == 6); CHECK(f.irq.level == 0);
    }
    wr(&f, UTXH, 0x55); CHECK(f.irq.level == 1);
    wr(&f, UTRSTAT, 0x20); CHECK(f.irq.level == 0);
    done(&f);
}
static void n45_control(void) {
    Fixture f; init(&f, false, true);
    wr(&f, UCON, 0x405); wr(&f, UTXH, 0x41);
    CHECK(rd(&f, UTRSTAT) == 6);
    CHECK(rd(&f, UINTSP) == 4); CHECK(rd(&f, UINTP) == 4);
    CHECK(f.irq.level == 1);
    wr(&f, UTRSTAT, 0x20); CHECK(f.irq.level == 1);
    wr(&f, UINTM, 4); CHECK(f.irq.level == 0);
    CHECK(rd(&f, UINTP) == 0); CHECK(rd(&f, UINTSP) == 4);
    wr(&f, UINTM, 0); CHECK(f.irq.level == 1);
    wr(&f, UINTP, 4); CHECK(f.irq.level == 0);
    CHECK(rd(&f, UINTSP) == 0); CHECK(rd(&f, UINTP) == 0);
    exynos4210_uart_cts(&f.state, 0, 1);
    CHECK(rd(&f, UMSTAT) == 1); CHECK(rd(&f, UTRSTAT) == 6);
    CHECK(f.irq.level == 0);
    const uint8_t byte = 0x52;
    exynos4210_uart_receive(&f.state, &byte, 1);
    CHECK(rd(&f, UINTSP) == 1); CHECK(f.irq.level == 1);
    CHECK(rd(&f, URXH) == byte);
    wr(&f, UINTP, 1); CHECK(f.irq.level == 0);
    /* Preserve the upstream N45 empty-FIFO IRQ behavior when legacy=false. */
    wr(&f, UFCON, 1); exynos4210_uart_update_irq(&f.state);
    CHECK(rd(&f, UINTP) == 4); CHECK(f.irq.level == 1);
    wr(&f, UINTP, 4); CHECK(rd(&f, UINTP) == 4);
    CHECK(f.irq.level == 1);
    wr(&f, UINTM, 4); CHECK(f.irq.level == 0);
    done(&f);
    init(&f, false, false);
    wr(&f, UTXH, 0x41);
    CHECK(rd(&f, UTRSTAT) == 6); CHECK(rd(&f, UINTSP) == 0);
    CHECK(f.state.chr.writes == 0); CHECK(f.irq.level == 0);
    done(&f);
}
int main(void) {
    original_configuration();
    transmit_and_ack(true); transmit_and_ack(false);
    cts_edges(); receive_timeout_and_drain();
    receive_full_drain_and_overrun();
    baud_register_storage(); n45_control();
    printf("%u UART MMIO and state assertions passed\n", checks);
    return 0;
}
"""


def make_harness(source):
    """Slice bounded production regions; fail if the expected structure drifts."""
    definitions_start = source.index("#define ULCON")
    definitions_end = source.index("/* Used only for tracing */")
    io_start = source.index("static const char *exynos4210_uart_regname")
    io_end = source.index("static const MemoryRegionOps exynos4210_uart_ops")
    receive_start = source.index("static int exynos4210_uart_can_receive")
    receive_end = source.index("static int exynos4210_uart_post_load")
    cts_start = source.index("static void exynos4210_uart_cts")
    cts_end = source.index("static void exynos4210_uart_init", cts_start)
    functions = source[io_start:io_end] + source[receive_start:receive_end]
    functions += source[cts_start:cts_end]
    for name in ("exynos4210_uart_write", "exynos4210_uart_read",
                 "exynos4210_uart_update_irq", "exynos4210_uart_receive",
                 "exynos4210_uart_timeout_int", "exynos4210_uart_cts"):
        if functions.count("static " + ("uint64_t " if name.endswith("_read")
                                      else "void ") + name + "(") != 1:
            raise ValueError(f"Expected exactly one production definition: {name}")
    traces = sorted(set(re.findall(r"\b(trace_exynos_uart_\w+)\s*\(", functions)))
    trace_stubs = "\n".join(f"#define {name}(...) ((void)0)" for name in traces)
    return (PRELUDE + "\n" + trace_stubs + "\n" +
            source[definitions_start:definitions_end] + functions + TESTS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--emit-c", type=Path,
                        help="Write the complete actual-source harness and exit without compiling")
    args = parser.parse_args()
    source = SOURCE.read_text()
    harness = make_harness(source)
    if args.emit_c:
        args.emit_c.parent.mkdir(parents=True, exist_ok=True)
        args.emit_c.write_text(harness)
        print(f"Wrote {args.emit_c}; no compile or test run requested")
        return
    compiler = shutil.which("clang") or shutil.which("cc")
    if not compiler:
        parser.error("A C compiler is required")
    with tempfile.TemporaryDirectory(prefix="iphoneos1-uart-tests-") as directory:
        c_path = Path(directory) / "uart.c"
        executable = Path(directory) / "uart-tests"
        c_path.write_text(harness)
        command = [compiler, "-std=c11", "-g", "-O1", "-fno-omit-frame-pointer",
                   "-fsanitize=address,undefined", str(c_path), "-o", str(executable)]
        subprocess.run(command, check=True, capture_output=True, text=True)
        result = subprocess.run([str(executable)], check=True, capture_output=True, text=True)
    print(result.stdout, end="")
    if args.report:
        count = int(result.stdout.split()[0])
        report = {
            "source": str(SOURCE.relative_to(ROOT)),
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "harness_sha256": hashlib.sha256(harness.encode()).hexdigest(),
            "compiler": compiler,
            "sanitizers": ["address", "undefined"],
            "assertions_passed": count,
            "output": result.stdout.strip(),
            "validation_boundary": "Production UART MMIO functions and register transitions with stubbed clock, IRQ and chardev; no VM, wire timing, UART DMA, baud measurement or baseband validation",
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
