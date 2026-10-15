#!/usr/bin/env python3
"""Compile and exercise the production timer4 model without launching a VM.

The controlled virtual clock and IRQ stand-ins test timer register semantics and
deadline arithmetic. They do not establish hardware clock-source/prescaler
behavior, FIQ routing, scheduling progress, or a successful iPhone UI boot.
Preparing this script does not compile or execute any part of the model.
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
QEMU = ROOT / "vendor/qemu"

PRELUDE = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>
typedef uint64_t hwaddr;
typedef struct { unsigned unused; } SysBusDevice;
typedef struct { unsigned unused; } MemoryRegion;
typedef struct { unsigned hz; } Clock;
typedef struct { bool armed; int64_t deadline; } QEMUTimer;
typedef int *qemu_irq;
#define OBJECT_DECLARE_SIMPLE_TYPE(Type, Name) typedef struct Type Type;
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define NANOSECONDS_PER_SECOND 1000000000U
#define QEMU_CLOCK_VIRTUAL 0
#define LOG_GUEST_ERROR 1
static int64_t virtual_ns;
static unsigned irq_raises, guest_errors;
static int64_t qemu_clock_get_ns(int clock) { (void)clock; return virtual_ns; }
static unsigned clock_get_hz(Clock *clk) { return clk->hz; }
static uint64_t muldiv64(uint64_t a, uint32_t b, uint32_t c) {
    assert(c); return (__uint128_t)a * b / c;
}
static uint64_t clock_ns_to_ticks(Clock *clk, uint64_t ns) {
    return muldiv64(ns, clk->hz, NANOSECONDS_PER_SECOND);
}
static void timer_del(QEMUTimer *timer) { timer->armed = false; }
static void timer_mod(QEMUTimer *timer, int64_t deadline) {
    assert(deadline >= virtual_ns);
    timer->armed = true; timer->deadline = deadline;
}
static void qemu_irq_raise(qemu_irq irq) { *irq = 1; irq_raises++; }
static void qemu_irq_lower(qemu_irq irq) { *irq = 0; }
static void qemu_log_mask(int mask, const char *format, ...) {
    (void)mask; (void)format; guest_errors++;
}
"""

TESTS = r"""
static unsigned checks;
#define CHECK(v) do { assert(v); checks++; } while (0)
static void setup(IPodTouchTimerState *s, QEMUTimer *timer, Clock *clk,
                  int *irq, bool m68) {
    memset(s, 0, sizeof(*s)); memset(timer, 0, sizeof(*timer));
    virtual_ns = 0; *irq = 0; clk->hz = 12000000;
    s->st_timer = timer; s->sysclk = clk; s->irq = irq;
    s->s5l8900_legacy = m68;
}
static void wr(IPodTouchTimerState *s, hwaddr addr, uint32_t value) {
    s5l8900_timer1_write(s, addr, value, 4);
}
static uint32_t rd(IPodTouchTimerState *s, hwaddr addr) {
    return s5l8900_timer1_read(s, addr, 4);
}
static void fire(IPodTouchTimerState *s) {
    CHECK(s->st_timer->armed && virtual_ns >= s->st_timer->deadline);
    s->st_timer->armed = false;
    s5l8900_st_tick(s);
}
int main(void) {
    IPodTouchTimerState s; QEMUTimer timer; Clock clk; int irq;
    const uint32_t counts[] = {0, 1, 10, 999, 1000, UINT32_MAX};
    const uint32_t rates[] = {6000000, 3000000, 750000, 187500, 12000000};

    /* Each supported divider produces a coherent count and rounded-up event. */
    for (unsigned selector = 0; selector < ARRAY_SIZE(rates); selector++) {
        for (unsigned n = 0; n < ARRAY_SIZE(counts); n++) {
            setup(&s, &timer, &clk, &irq, true);
            wr(&s, TIMER_4 + TIMER_CONFIG, 0x7000 | (selector << 8));
            CHECK(rd(&s, TIMER_4 + TIMER_CONFIG) ==
                  (0x7000 | (selector << 8)));
            wr(&s, TIMER_4 + TIMER_COUNT_BUFFER, counts[n]);
            CHECK(rd(&s, TIMER_4 + TIMER_COUNT_BUFFER) == counts[n]);
            wr(&s, TIMER_4 + TIMER_STATE, 3);
            uint64_t numerator = (uint64_t)counts[n] * 1000000000ULL;
            uint64_t delay = numerator / rates[selector] +
                             !!(numerator % rates[selector]);
            if (!delay) delay = 1;
            CHECK(timer.armed && timer.deadline == delay);
            CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == counts[n]);
            virtual_ns = timer.deadline - 1;
            if (counts[n]) CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) > 0);
            CHECK(!irq);
            virtual_ns++;
            CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 0);
            unsigned before = irq_raises; fire(&s);
            CHECK(irq && irq_raises == before + 1);
            CHECK(!timer.armed && !s.legacy_running);
            CHECK(rd(&s, TIMER_4 + TIMER_COUNT_BUFFER) == counts[n]);
            wr(&s, TIMER_IRQLATCH, UINT32_MAX); CHECK(!irq);
        }
    }

    /* 60000 ticks at 6 MHz takes exactly 10 ms; STOP freezes current count. */
    setup(&s, &timer, &clk, &irq, true);
    wr(&s, TIMER_4 + TIMER_COUNT_BUFFER, 60000);
    wr(&s, TIMER_4 + TIMER_STATE, 3);
    CHECK(timer.deadline == 10000000);
    virtual_ns = 4000000;
    CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 36000);
    wr(&s, TIMER_4 + TIMER_STATE, 0);
    CHECK(!timer.armed && rd(&s, TIMER_4 + TIMER_STATE) == 0);
    virtual_ns = 1000000000;
    CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 36000);
    wr(&s, TIMER_4 + TIMER_STATE, 1);
    CHECK(timer.armed && timer.deadline == 1006000000);
    virtual_ns = timer.deadline; fire(&s);
    CHECK(timer.armed && timer.deadline == 1016000000);
    CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 60000);
    wr(&s, TIMER_IRQLATCH, 0); CHECK(!irq);

    /* Config changes synchronize old-rate ticks before selecting the new rate. */
    setup(&s, &timer, &clk, &irq, true);
    wr(&s, TIMER_4 + TIMER_COUNT_BUFFER, 60000);
    wr(&s, TIMER_4 + TIMER_STATE, 3);
    virtual_ns = 4000000;
    wr(&s, TIMER_4 + TIMER_CONFIG, 4 << 8);
    CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 36000);
    CHECK(timer.deadline == 7000000);
    virtual_ns = 4500000;
    CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 30000);
    unsigned errors = guest_errors;
    wr(&s, TIMER_4 + TIMER_CONFIG, 5 << 8);
    CHECK(!timer.armed && guest_errors == errors + 1);
    virtual_ns = 1000000000;
    CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 30000);
    wr(&s, TIMER_4 + TIMER_CONFIG, 4 << 8);
    CHECK(timer.armed && timer.deadline == 1002500000);

    /* Manual update loads while stopped; later buffer writes wait for reload. */
    setup(&s, &timer, &clk, &irq, true);
    wr(&s, TIMER_4 + TIMER_COUNT_BUFFER, 60000);
    wr(&s, TIMER_4 + TIMER_COUNT_BUFFER2, 123);
    wr(&s, TIMER_4 + TIMER_PRESCALER, 17);
    CHECK(rd(&s, TIMER_4 + TIMER_COUNT_BUFFER2) == 123);
    CHECK(rd(&s, TIMER_4 + TIMER_PRESCALER) == 17);
    wr(&s, TIMER_4 + TIMER_STATE, 2);
    CHECK(!timer.armed && rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 60000);
    wr(&s, TIMER_4 + TIMER_STATE, 1);
    virtual_ns = 4000000;
    wr(&s, TIMER_4 + TIMER_COUNT_BUFFER, 120000);
    CHECK(rd(&s, TIMER_4 + TIMER_COUNT_BUFFER) == 120000);
    CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 36000);
    wr(&s, TIMER_4 + TIMER_STATE, 3);
    CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 120000);
    CHECK(timer.deadline == 24000000);

    /* Either absolute-counter word can be read first and always advances. */
    setup(&s, &timer, &clk, &irq, true);
    virtual_ns = 1000000000;
    CHECK(rd(&s, TIMER_TICKSLOW) == 6000000);
    CHECK(rd(&s, TIMER_TICKSHIGH) == 0);
    virtual_ns += 1000000000;
    CHECK(rd(&s, TIMER_TICKSLOW) == 12000000);
    virtual_ns = 8000000000000LL;
    uint64_t ticks = muldiv64(virtual_ns / 2, clk.hz, 1000000000);
    CHECK(rd(&s, TIMER_TICKSHIGH) == (ticks >> 32));
    CHECK(rd(&s, TIMER_TICKSLOW) == (uint32_t)ticks);
    uint64_t rollover = (((1ULL << 32) * 1000000000ULL + clk.hz - 1) /
                         clk.hz) * 2;
    virtual_ns = rollover - 2;
    CHECK(rd(&s, TIMER_TICKSHIGH) == 0);
    CHECK(rd(&s, TIMER_TICKSLOW) == UINT32_MAX);
    virtual_ns = rollover;
    CHECK(rd(&s, TIMER_TICKSHIGH) == 1);
    CHECK(rd(&s, TIMER_TICKSLOW) == 0);
    CHECK(rd(&s, TIMER_TICKSHIGH) == 1);

    /* Huge clock epochs are bounded without bringing expiry forward. */
    setup(&s, &timer, &clk, &irq, true);
    virtual_ns = INT64_MAX - 1;
    wr(&s, TIMER_4 + TIMER_COUNT_BUFFER, UINT32_MAX);
    errors = guest_errors;
    wr(&s, TIMER_4 + TIMER_STATE, 3);
    CHECK(!timer.armed && !irq && guest_errors == errors + 1);
    CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == UINT32_MAX);

    /* Control: N45 retains its original readback and 1000-tick floor. */
    setup(&s, &timer, &clk, &irq, false);
    wr(&s, TIMER_4 + TIMER_COUNT_BUFFER, 10);
    CHECK(rd(&s, TIMER_4 + TIMER_COUNT_BUFFER) == 0);
    CHECK(rd(&s, TIMER_4 + TIMER_CURRENT_COUNT) == 0);
    wr(&s, TIMER_4 + TIMER_STATE, 3);
    CHECK(timer.armed && timer.deadline == 100000);
    CHECK(rd(&s, TIMER_IRQSTAT) == UINT32_MAX);
    virtual_ns = timer.deadline; fire(&s); CHECK(irq && !timer.armed);
    printf("{\"checks\":%u,\"irq_raises\":%u,\"guest_errors\":%u}\n",
           checks, irq_raises, guest_errors);
    return 0;
}
"""


def without_includes(source):
    return re.sub(r"^\s*#include[^\n]*\n", "", source, flags=re.MULTILINE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    compiler = shutil.which(args.cc)
    if not compiler:
        parser.error(f"Compiler not found: {args.cc}")
    model_path = QEMU / "hw/arm/ipod_touch_timer.c"
    header_path = QEMU / "include/hw/arm/ipod_touch_timer.h"
    model = model_path.read_text()
    header = header_path.read_text()
    marker = "static const MemoryRegionOps timer1_ops"
    if model.count(marker) != 1:
        raise RuntimeError("Timer extraction boundary changed; inspect source")
    production = without_includes(model.split(marker)[0])
    unit = PRELUDE + without_includes(header) + production + TESTS
    with tempfile.TemporaryDirectory(prefix="iphoneos1-timer-test-") as td:
        source = Path(td) / "timer-test.c"
        executable = Path(td) / "timer-test"
        source.write_text(unit)
        subprocess.run([
            compiler, "-std=c11", "-O1", "-g", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", str(source), "-o", str(executable),
        ], check=True, timeout=60)
        completed = subprocess.run(
            [str(executable)], check=True, capture_output=True, text=True,
            timeout=30,
        )
    result = json.loads(completed.stdout)
    result.update({
        "source": str(model_path),
        "source_sha256": hashlib.sha256(model.encode()).hexdigest(),
        "header_sha256": hashlib.sha256(header.encode()).hexdigest(),
        "sanitizers": ["address", "undefined"],
        "scope": "Actual timer model/state with controlled virtual clock and IRQ stand-ins; no VM or hardware/UI claim",
    })
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")


if __name__ == "__main__":
    main()
