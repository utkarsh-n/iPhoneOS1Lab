#!/usr/bin/env python3
"""Test the production NAND page and FIFO paths without booting QEMU.

The actual NAND state declarations and C reader, page publisher, buffer switch,
MMIO read and MMIO write functions are compiled with small POSIX/QEMU stand-ins.
This verifies file semantics and register-driven data movement, not NAND timing,
FTL consistency, DMA wiring, concurrent access, or a guest filesystem boot.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
QEMU = ROOT / "vendor/qemu"

PRELUDE = r"""
#define _DARWIN_C_SOURCE
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
typedef struct { unsigned unused; } SysBusDevice;
typedef struct { unsigned unused; } MemoryRegion;
typedef struct { unsigned unused; } QemuMutex;
typedef unsigned qemu_irq;
typedef uint64_t hwaddr;
#define OBJECT_DECLARE_SIMPLE_TYPE(a, b)
static void automatic_free(char **p) { free(*p); }
#define g_autofree __attribute__((cleanup(automatic_free)))
static char *g_strdup_printf(const char *format, ...) {
    char *result = NULL; va_list ap; va_start(ap, format);
    int count = vasprintf(&result, format, ap); va_end(ap);
    assert(count >= 0 && result); return result;
}
#define g_mkstemp mkstemp
#define g_strerror strerror
static void qemu_mutex_lock(QemuMutex *lock) { (void)lock; }
static void qemu_mutex_unlock(QemuMutex *lock) { (void)lock; }
static void hw_error(const char *format, ...) {
    va_list ap; va_start(ap, format); vfprintf(stderr, format, ap);
    va_end(ap); fputc('\n', stderr); exit(2);
}
"""

TESTS = r"""
#define PAGE_SIZE (NAND_BYTES_PER_PAGE + NAND_BYTES_PER_SPARE)
static unsigned checks;
#define CHECK(v) do { assert(v); checks++; } while (0)

static void make_pattern(uint8_t *bytes, uint8_t seed) {
    for (unsigned i = 0; i < PAGE_SIZE; i++) {
        bytes[i] = seed + i * 37 + (i >> 8);
    }
}
static void page_filename(char *out, size_t length, const char *directory,
                          unsigned bank, unsigned page, bool legacy) {
    int count = snprintf(out, length, "%s/bank%u/%u%s.page", directory,
                         bank, page, legacy ? "_new" : "");
    CHECK(count > 0 && (size_t)count < length);
}
static void write_fixture(const char *directory, unsigned bank, unsigned page,
                          const uint8_t *bytes, unsigned length) {
    char filename[4096];
    page_filename(filename, sizeof(filename), directory, bank, page, false);
    FILE *f = fopen(filename, "wb"); CHECK(f);
    CHECK(fwrite(bytes, 1, length, f) == length); CHECK(!fclose(f));
}
static void expect_disk_page(const char *directory, unsigned bank,
                             unsigned page, bool legacy, const uint8_t *expected) {
    char filename[4096]; uint8_t bytes[PAGE_SIZE]; struct stat info;
    page_filename(filename, sizeof(filename), directory, bank, page, legacy);
    CHECK(!stat(filename, &info)); CHECK(info.st_size == PAGE_SIZE);
    FILE *f = fopen(filename, "rb"); CHECK(f);
    CHECK(fread(bytes, 1, sizeof(bytes), f) == sizeof(bytes));
    CHECK(fgetc(f) == EOF && !ferror(f)); CHECK(!fclose(f));
    CHECK(!memcmp(bytes, expected, sizeof(bytes)));
}
static unsigned count_pages(const char *directory) {
    unsigned count = 0;
    for (unsigned bank = 0; bank < NAND_NUM_BANKS; bank++) {
        char path[4096];
        int length = snprintf(path, sizeof(path), "%s/bank%u", directory, bank);
        CHECK(length > 0 && (size_t)length < sizeof(path));
        DIR *d = opendir(path); CHECK(d);
        struct dirent *entry;
        while ((entry = readdir(d))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
                continue;
            }
            CHECK(!strstr(entry->d_name, ".tmp-"));
            CHECK(strstr(entry->d_name, ".page") != NULL); count++;
        }
        CHECK(!closedir(d));
    }
    return count;
}
static ITNandState *new_state(char *base, char *overlay, uint8_t erased_fill) {
    ITNandState *s = calloc(1, sizeof(*s)); CHECK(s);
    s->nand_path = base; s->nand_overlay = overlay;
    s->erased_page_fill = erased_fill;
    s->bank_mask = 0xff;
    s->page_buffer = malloc(NAND_BYTES_PER_PAGE); CHECK(s->page_buffer);
    s->page_spare_buffer = malloc(NAND_BYTES_PER_SPARE); CHECK(s->page_spare_buffer);
    s->buffered_bank = UINT32_MAX; s->buffered_page = UINT32_MAX;
    return s;
}
static void free_state(ITNandState *s) {
    free(s->page_buffer); free(s->page_spare_buffer); free(s);
}
static void expect_read(ITNandState *s, unsigned bank, unsigned page,
                        const uint8_t *expected) {
    uint8_t data[NAND_BYTES_PER_PAGE], spare[NAND_BYTES_PER_SPARE];
    memset(data, 0x5a, sizeof(data)); memset(spare, 0x5a, sizeof(spare));
    nand_read_page(s, bank, page, data, spare);
    CHECK(!memcmp(data, expected, sizeof(data)));
    CHECK(!memcmp(spare, expected + sizeof(data), sizeof(spare)));
}
static void expect_nullable_read(ITNandState *s, unsigned bank, unsigned page,
                                 const uint8_t *expected) {
    uint8_t data[NAND_BYTES_PER_PAGE], spare[NAND_BYTES_PER_SPARE];
    memset(data, 0x5a, sizeof(data)); memset(spare, 0x5a, sizeof(spare));
    nand_read_page(s, bank, page, NULL, spare);
    CHECK(!memcmp(spare, expected + sizeof(data), sizeof(spare)));
    nand_read_page(s, bank, page, data, NULL);
    CHECK(!memcmp(data, expected, sizeof(data)));
    nand_read_page(s, bank, page, NULL, NULL);
    CHECK(true);
}
static void select_page(ITNandState *s, unsigned bank, unsigned page) {
    set_bank(s, bank); nand_set_buffered_page(s, page);
    CHECK(s->buffered_bank == bank && s->buffered_page == page);
}
static void expect_fifo_read(ITNandState *s, unsigned bank, unsigned page,
                             const uint8_t *expected) {
    set_bank(s, bank);
    itnand_write(s, NAND_FMADDR0, (page & 0xffff) << 16, 4);
    itnand_write(s, NAND_FMADDR1, page >> 16, 4);
    itnand_write(s, NAND_CMD, NAND_CMD_READ, 4);
    itnand_write(s, NAND_FMDNUM, NAND_BYTES_PER_PAGE - 1, 4);
    for (unsigned i = 0; i < NAND_BYTES_PER_PAGE; i += 4) {
        uint32_t value; memcpy(&value, expected + i, 4);
        CHECK(itnand_read(s, NAND_FMFIFO, 4) == value);
    }
    itnand_write(s, NAND_FMDNUM, NAND_BYTES_PER_SPARE - 1, 4);
    for (unsigned i = 0; i < NAND_BYTES_PER_SPARE; i += 4) {
        uint32_t value; memcpy(&value, expected + NAND_BYTES_PER_PAGE + i, 4);
        CHECK(itnand_read(s, NAND_FMFIFO, 4) == value);
    }
}
static void fifo_program(ITNandState *s, unsigned bank, unsigned page,
                         const uint8_t *bytes) {
    select_page(s, bank, page);
    memcpy(s->page_spare_buffer, bytes + NAND_BYTES_PER_PAGE, NAND_BYTES_PER_SPARE);
    itnand_write(s, NAND_FMDNUM, NAND_BYTES_PER_PAGE, 4);
    s->is_writing = true;
    for (unsigned i = 0; i < NAND_BYTES_PER_PAGE; i += 4) {
        uint32_t value; memcpy(&value, bytes + i, 4);
        itnand_write(s, NAND_FMFIFO, value, 4);
        CHECK(s->is_writing == (i + 4 < NAND_BYTES_PER_PAGE));
    }
    CHECK(!s->fmdnum);
}

int main(int argc, char **argv) {
    assert(argc >= 3);
    char *base = argv[1], *overlay = argv[2];
    uint8_t original0[PAGE_SIZE], original1[PAGE_SIZE], programmed0[PAGE_SIZE],
            programmed1[PAGE_SIZE], replacement[PAGE_SIZE], erased[PAGE_SIZE];
    make_pattern(original0, 11); make_pattern(original1, 99);
    make_pattern(programmed0, 178); make_pattern(programmed1, 201);
    make_pattern(replacement, 251);
    write_fixture(base, 0, 17, original0, sizeof(original0));
    write_fixture(base, 1, 19, original1, sizeof(original1));
    ITNandState *s = new_state(base, overlay, 0xff);
    if (argc > 3) {
        const char *mode = argv[3];
        if (!strcmp(mode, "truncated-overlay")) {
            write_fixture(overlay, 0, 17, programmed0, 128);
            nand_read_page(s, 0, 17, NULL, s->page_spare_buffer);
        } else if (!strcmp(mode, "truncated-base")) {
            write_fixture(base, 0, 17, original0, 64);
            nand_read_page(s, 0, 17, s->page_buffer, s->page_spare_buffer);
        } else if (!strcmp(mode, "oversized-overlay")) {
            char filename[4096];
            write_fixture(overlay, 0, 17, programmed0, sizeof(programmed0));
            page_filename(filename, sizeof(filename), overlay, 0, 17, false);
            FILE *f = fopen(filename, "ab"); CHECK(f);
            CHECK(fputc(0, f) != EOF); CHECK(!fclose(f));
            nand_read_page(s, 0, 17, s->page_buffer, s->page_spare_buffer);
        } else if (!strcmp(mode, "invalid-read-bank")) {
            nand_read_page(s, NAND_NUM_BANKS, 0, s->page_buffer, s->page_spare_buffer);
        } else if (!strcmp(mode, "invalid-read-page")) {
            nand_read_page(s, 0, NAND_PAGES_PER_BANK, s->page_buffer, s->page_spare_buffer);
        } else if (!strcmp(mode, "invalid-flush-bank")) {
            s->buffered_bank = NAND_NUM_BANKS; s->buffered_page = 0; nand_flush_page(s);
        } else if (!strcmp(mode, "invalid-flush-page")) {
            s->buffered_bank = 0; s->buffered_page = NAND_PAGES_PER_BANK; nand_flush_page(s);
        } else {
            fprintf(stderr, "Unknown rejection case: %s\n", mode); return 3;
        }
        return 1;
    }
    for (unsigned bank = 0; bank < NAND_NUM_BANKS; bank++) {
        s->fmctrl0 = 1u << (bank + 1);
        s->cmd = NAND_CMD_ID;
        CHECK(itnand_read(s, NAND_FMFIFO, 4) == NAND_CHIP_ID);
    }
    s->bank_mask = 0x0f;
    for (unsigned bank = 0; bank < NAND_NUM_BANKS; bank++) {
        s->fmctrl0 = 1u << (bank + 1);
        CHECK(itnand_read(s, NAND_FMFIFO, 4) ==
              (bank < 4 ? NAND_CHIP_ID : UINT32_MAX));
    }
    s->fmctrl0 = 0;
    CHECK(itnand_read(s, NAND_FMFIFO, 4) == UINT32_MAX);
    s->bank_mask = 0xff;
    expect_read(s, 0, 17, original0); expect_nullable_read(s, 0, 17, original0);
    memset(erased, 0xff, sizeof(erased));
    expect_read(s, 7, NAND_PAGES_PER_BANK - 1, erased);
    expect_nullable_read(s, 7, NAND_PAGES_PER_BANK - 1, erased);
    fifo_program(s, 0, 17, programmed0);
    expect_disk_page(overlay, 0, 17, false, programmed0);
    select_page(s, 1, 19); CHECK(!memcmp(s->page_buffer, original1, NAND_BYTES_PER_PAGE));
    expect_fifo_read(s, 0, 17, programmed0);
    expect_nullable_read(s, 0, 17, programmed0);
    fifo_program(s, 1, 19, programmed1);
    expect_fifo_read(s, 0, 17, programmed0);
    expect_fifo_read(s, 1, 19, programmed1);
    expect_disk_page(base, 0, 17, false, original0);
    expect_disk_page(base, 1, 19, false, original1);
    CHECK(count_pages(overlay) == 2);
    free_state(s);
    s = new_state(base, overlay, 0xff);
    expect_read(s, 0, 17, programmed0); expect_read(s, 1, 19, programmed1);
    select_page(s, 0, 17);
    memcpy(s->page_buffer, replacement, NAND_BYTES_PER_PAGE);
    memcpy(s->page_spare_buffer, replacement + NAND_BYTES_PER_PAGE, NAND_BYTES_PER_SPARE);
    nand_flush_page(s);
    expect_disk_page(overlay, 0, 17, false, replacement);
    CHECK(count_pages(overlay) == 2);
    expect_disk_page(base, 0, 17, false, original0);
    free_state(s);
    s = new_state(base, NULL, 0);
    memset(erased, 0, sizeof(erased)); erased[NAND_BYTES_PER_PAGE + 0xa] = 0xff;
    expect_read(s, 7, NAND_PAGES_PER_BANK - 1, erased);
    expect_nullable_read(s, 7, NAND_PAGES_PER_BANK - 1, erased);
    expect_read(s, 0, 17, original0);
    fifo_program(s, 0, 17, programmed0);
    expect_disk_page(base, 0, 17, true, programmed0);
    expect_disk_page(base, 0, 17, false, original0);
    free_state(s);
    s = new_state(base, "", 0);
    expect_read(s, 0, 17, original0); free_state(s);
    printf("%u page, persistence, file publication and FIFO assertions passed\n", checks);
    return 0;
}
"""

REJECTIONS = (
    "truncated-overlay", "truncated-base", "oversized-overlay",
    "invalid-read-bank", "invalid-read-page", "invalid-flush-bank",
    "invalid-flush-page",
)


def page_directories(root):
    for directory in (root / "base", root / "overlay"):
        directory.mkdir()
        for bank in range(8):
            (directory / f"bank{bank}").mkdir()
    return root / "base", root / "overlay"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    compiler = shutil.which("clang") or shutil.which("cc")
    if not compiler:
        raise SystemExit("No local C compiler available")
    header_path = QEMU / "include/hw/arm/ipod_touch_nand.h"
    source_path = QEMU / "hw/arm/ipod_touch_nand.c"
    header = header_path.read_text()
    declarations = header[header.index("#define NAND_NUM_BANKS"):
                          header.index("void nand_read_page")]
    source = source_path.read_text()
    functions = source[source.index("static void nand_validate_page"):
                       source.index("static const MemoryRegionOps nand_ops")]
    with tempfile.TemporaryDirectory(prefix="iphoneos1-nand-test-") as directory:
        directory = Path(directory)
        program = directory / "nand.c"
        binary = directory / "nand"
        program.write_text(PRELUDE + declarations + functions + TESTS)
        build = subprocess.run([compiler, "-std=c11", "-O1", "-g",
                                "-fsanitize=address,undefined", str(program),
                                "-o", str(binary)], timeout=30,
                               capture_output=True, text=True)
        if build.returncode:
            raise RuntimeError(f"Production NAND harness compilation failed:\n{build.stderr}")
        positive_root = directory / "positive"
        positive_root.mkdir()
        base, overlay = page_directories(positive_root)
        positive = subprocess.run([str(binary), str(base), str(overlay)],
                                  timeout=15, capture_output=True, text=True)
        if positive.returncode:
            raise AssertionError(f"Production NAND assertions failed:\n{positive.stdout}\n{positive.stderr}")
        positive_files = {
            str(path.relative_to(positive_root)): {
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in sorted(positive_root.rglob("*.page"))
        }
        rejected = []
        for mode in REJECTIONS:
            reject_root = directory / mode
            reject_root.mkdir()
            base, overlay = page_directories(reject_root)
            result = subprocess.run([str(binary), str(base), str(overlay), mode],
                                    timeout=15, capture_output=True, text=True)
            if result.returncode != 2 or "NAND:" not in result.stderr:
                raise AssertionError(f"{mode} was not explicitly rejected: {result}")
            rejected.append({"case": mode, "exit_code": result.returncode,
                             "diagnostic": result.stderr.strip()})
    report = {
        "production_source": str(source_path),
        "production_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "production_header_sha256": hashlib.sha256(header.encode()).hexdigest(),
        "compiler": compiler,
        "sanitizers": ["address", "undefined"],
        "result": positive.stdout.strip(),
        "published_files": positive_files,
        "rejected_cases": rejected,
        "validation_boundary": "Production page reader, flush, bank/page buffer switching, "
        "and MMIO FIFO data path with POSIX file operations and mutex stand-ins; "
        "no concurrent publication, controller timing, FTL consistency, DMA, or guest boot check",
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
