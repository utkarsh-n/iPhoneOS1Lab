#!/usr/bin/env python3
"""Exercise production SYSIC GPIO polarity, masks, levels and W1C behavior."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'vendor/qemu/hw/arm/ipod_touch_sysic.c'
HEADER = ROOT/'vendor/qemu/include/hw/arm/ipod_touch_sysic.h'
PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef unsigned qemu_irq;
typedef uint64_t hwaddr;
typedef unsigned SysBusDevice;
typedef unsigned MemoryRegion;
typedef unsigned DeviceState;
#define IPOD_TOUCH_SYSIC(dev) ((IPodTouchSYSICState *)(dev))
static unsigned levels[8], checks;
static void qemu_set_irq(qemu_irq irq, int high) {
    if (irq > 7 || (high != 0 && high != 1)) abort();
    levels[irq] = high;
}
static void qemu_irq_raise(qemu_irq irq) { qemu_set_irq(irq, 1); }
static void qemu_irq_lower(qemu_irq irq) { qemu_set_irq(irq, 0); }
static void hw_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr); exit(2);
}
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "check failed line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
'''
TESTS = r'''
int main(int argc, char **argv) {
    IPodTouchSYSICState s = {0};
    s.iphone_2g = true;
    for (unsigned i = 0; i < GPIO_NUMINTGROUPS; i++) s.gpio_irqs[i] = i + 1;
    if (argc > 1) {
        if (!strcmp(argv[1], "input")) ipod_touch_sysic_gpio_input(&s, 224, true);
        else ipod_touch_sysic_gpio_event(&s, 224);
        return 1;
    }
    for (unsigned group = 0; group < GPIO_NUMINTGROUPS; group++) {
        unsigned interrupt = group * 32 + 31;
        uint32_t bit = UINT32_C(1) << 31;
        hwaddr polarity = GPIO_INTLEVEL + group * 4;
        hwaddr type = GPIO_INTTYPE + group * 4;
        hwaddr mask = GPIO_INTEN + group * 4;
        hwaddr status = GPIO_INTSTAT + group * 4;
        ipod_touch_sysic_gpio_input(&s, interrupt, true);
        ipod_touch_sysic_write(&s, type, bit, 4);
        ipod_touch_sysic_write(&s, mask, bit, 4);
        CHECK(!levels[group+1]); CHECK(!ipod_touch_sysic_read(&s, status, 4));
        ipod_touch_sysic_gpio_input(&s, interrupt, false);
        CHECK(levels[group+1]); CHECK(ipod_touch_sysic_read(&s, status, 4) == bit);
        ipod_touch_sysic_write(&s, status, bit, 4);
        CHECK(levels[group+1]); /* Held level survives W1C. */
        ipod_touch_sysic_write(&s, polarity, bit, 4);
        CHECK(!levels[group+1]); CHECK(!ipod_touch_sysic_read(&s, status, 4));
        CHECK(ipod_touch_sysic_read(&s, polarity, 4) == bit);
        ipod_touch_sysic_gpio_input(&s, interrupt, true);
        CHECK(levels[group+1]);
        ipod_touch_sysic_write(&s, polarity, 0, 4);
        CHECK(!levels[group+1]);
        /* Edge status latches and can be masked, then cleared selectively. */
        ipod_touch_sysic_write(&s, type, 0, 4);
        ipod_touch_sysic_write(&s, mask, 0, 4);
        ipod_touch_sysic_gpio_input(&s, interrupt, false);
        CHECK(!levels[group+1]); CHECK(ipod_touch_sysic_read(&s, status, 4) == bit);
        ipod_touch_sysic_write(&s, mask, bit, 4);
        CHECK(levels[group+1]);
        ipod_touch_sysic_write(&s, status, bit, 4);
        CHECK(!levels[group+1]); CHECK(!ipod_touch_sysic_read(&s, status, 4));
        ipod_touch_sysic_gpio_input(&s, interrupt, false);
        CHECK(!levels[group+1]);
        ipod_touch_sysic_gpio_event(&s, interrupt);
        CHECK(levels[group+1]);
        ipod_touch_sysic_write(&s, mask, 0, 4);
        CHECK(!levels[group+1]);
        ipod_touch_sysic_write(&s, status, bit, 4);
        CHECK(!ipod_touch_sysic_read(&s, status, 4));
    }
    /* Original DT flags 7: Home is high-level with guest polarity auto-flip. */
    ipod_touch_sysic_gpio_input(&s, 0x28, false);
    ipod_touch_sysic_write(&s, GPIO_INTLEVEL+4, 0x100, 4);
    ipod_touch_sysic_write(&s, GPIO_INTTYPE+4, 0x100, 4);
    ipod_touch_sysic_write(&s, GPIO_INTEN+4, 0x100, 4);
    CHECK(!levels[2]);
    ipod_touch_sysic_gpio_input(&s, 0x28, true); CHECK(levels[2]);
    ipod_touch_sysic_write(&s, GPIO_INTLEVEL+4, 0, 4); CHECK(!levels[2]);
    ipod_touch_sysic_gpio_input(&s, 0x28, false); CHECK(levels[2]);
    ipod_touch_sysic_write(&s, GPIO_INTLEVEL+4, 0x100, 4); CHECK(!levels[2]);
    /* Original volume flags 5: idle-high, low-level with guest auto-flip. */
    ipod_touch_sysic_gpio_input(&s, 0x29, true);
    ipod_touch_sysic_write(&s, GPIO_INTTYPE+4, 0x300, 4);
    ipod_touch_sysic_write(&s, GPIO_INTEN+4, 0x300, 4); CHECK(!levels[2]);
    ipod_touch_sysic_gpio_input(&s, 0x29, false); CHECK(levels[2]);
    ipod_touch_sysic_write(&s, GPIO_INTSTAT+4, 0x200, 4); CHECK(levels[2]);
    ipod_touch_sysic_write(&s, GPIO_INTLEVEL+4, 0x300, 4); CHECK(!levels[2]);
    ipod_touch_sysic_gpio_input(&s, 0x29, true); CHECK(levels[2]);
    ipod_touch_sysic_write(&s, GPIO_INTLEVEL+4, 0x100, 4); CHECK(!levels[2]);
    /* Selective W1C must preserve another source in the same group. */
    ipod_touch_sysic_write(&s, GPIO_INTTYPE+12, 0, 4);
    ipod_touch_sysic_write(&s, GPIO_INTEN+12, 0, 4);
    ipod_touch_sysic_gpio_event(&s, 3*32+2);
    ipod_touch_sysic_gpio_event(&s, 3*32+6);
    CHECK(!levels[4]);
    CHECK(ipod_touch_sysic_read(&s, GPIO_INTSTAT+12, 4) == 0x44);
    ipod_touch_sysic_write(&s, GPIO_INTEN+12, 0x44, 4); CHECK(levels[4]);
    ipod_touch_sysic_write(&s, GPIO_INTSTAT+12, 4, 4);
    CHECK(levels[4]); CHECK(ipod_touch_sysic_read(&s, GPIO_INTSTAT+12, 4) == 0x40);
    ipod_touch_sysic_write(&s, GPIO_INTSTAT+12, 0x40, 4); CHECK(!levels[4]);
    /* A held level remains pending while an independent edge is cleared. */
    ipod_touch_sysic_gpio_input(&s, 3*32+2, true);
    ipod_touch_sysic_write(&s, GPIO_INTLEVEL+12, 4, 4);
    ipod_touch_sysic_write(&s, GPIO_INTTYPE+12, 4, 4); CHECK(levels[4]);
    ipod_touch_sysic_gpio_event(&s, 3*32+6);
    CHECK(ipod_touch_sysic_read(&s, GPIO_INTSTAT+12, 4) == 0x44);
    ipod_touch_sysic_write(&s, GPIO_INTSTAT+12, 0x40, 4);
    CHECK(levels[4]); CHECK(ipod_touch_sysic_read(&s, GPIO_INTSTAT+12, 4) == 4);
    ipod_touch_sysic_write(&s, GPIO_INTSTAT+12, 4, 4); CHECK(levels[4]);
    ipod_touch_sysic_gpio_input(&s, 3*32+2, false); CHECK(!levels[4]);
    /* Padding slots must not index an eighth group. */
    CHECK(ipod_touch_sysic_read(&s, GPIO_INTSTAT+28, 4) == 0);
    ipod_touch_sysic_write(&s, GPIO_INTTYPE+28, 0xffffffff, 4);
    CHECK(s.iphone_2g);
    /* Reset clears logical configuration but preserves physical input levels. */
    ipod_touch_sysic_gpio_input(&s, 0x28, true);
    CHECK(levels[2]);
    ipod_touch_sysic_reset((DeviceState *)&s);
    for (unsigned group = 0; group < GPIO_NUMINTGROUPS; group++) {
        CHECK(!levels[group+1]); CHECK(!s.gpio_int_status[group]);
        CHECK(!s.gpio_int_enabled[group]); CHECK(!s.gpio_int_type[group]);
        CHECK(!s.gpio_int_level[group]);
    }
    CHECK((s.gpio_input_level[1] & 0x100) && (s.gpio_input_known[1] & 0x100));
    /* The N45 event path retains its legacy unmasked event. */
    s.iphone_2g = false;
    ipod_touch_sysic_gpio_event(&s, 0xa3); CHECK(levels[6]);
    ipod_touch_sysic_reset((DeviceState *)&s); CHECK(levels[6]);
    ipod_touch_sysic_write(&s, GPIO_INTSTAT+20, 8, 4); CHECK(!levels[6]);
    printf("%u SYSIC GPIO assertions passed\n", checks);
}
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--emit-c', type=Path)
    args = parser.parse_args()
    source, header = SOURCE.read_text(), HEADER.read_text()
    declarations = header[header.index('#define POWER_ID'):header.index('void ipod_touch_sysic_gpio_input')]
    functions = source[source.index('static void ipod_touch_sysic_update_gpio'):source.index('static const MemoryRegionOps')]
    reset = source[source.index('static void ipod_touch_sysic_reset'):source.index('static void ipod_touch_sysic_class_init')]
    program = PRELUDE+declarations+functions+reset+TESTS
    if args.emit_c:
        args.emit_c.write_text(program)
        return
    compiler = shutil.which('clang')
    if not compiler:
        raise SystemExit('No C compiler available')
    with tempfile.TemporaryDirectory(prefix='iphoneos1-sysic-test-') as temp:
        temp = Path(temp)
        cfile, binary = temp/'sysic.c', temp/'sysic'
        cfile.write_text(program)
        subprocess.run([compiler, '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                        str(cfile), '-o', str(binary)], check=True, timeout=30)
        result = subprocess.run([str(binary)], check=True, text=True, capture_output=True, timeout=10)
        rejected = []
        for mode in ['input', 'event']:
            out = subprocess.run([str(binary), mode], text=True, capture_output=True, timeout=10)
            if out.returncode != 2 or 'SYSIC: invalid GPIO' not in out.stderr:
                raise AssertionError(out)
            rejected.append({'case': mode, 'diagnostic': out.stderr.strip()})
    report = {'production_source_sha256': hashlib.sha256(source.encode()).hexdigest(),
              'result': result.stdout.strip(), 'rejected': rejected,
              'sanitizers': ['address', 'undefined'],
              'boundary': 'Register/input semantics and IRQ levels; no GPIO timing or guest interaction proof'}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
