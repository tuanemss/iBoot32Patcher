#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <include/config_finder.h>
#include <include/functions.h>
#include <include/iBoot32Patcher.h>

static bool parse_pattern(const char* text, uint8_t* bytes, char* mask, size_t cap, size_t* out_len) {
    size_t len = 0;
    const char* p = text;

    while(*p) {
        while(*p == ' ') {
            p++;
        }
        if(!*p) {
            break;
        }
        if(len >= cap) {
            return false;
        }
        if(p[0] == '?' && p[1] == '?') {
            bytes[len] = 0;
            mask[len] = '?';
            p += 2;
        } else {
            char hex[3] = { p[0], p[1], 0 };
            char* end = NULL;
            unsigned long value = strtoul(hex, &end, 16);
            if(end != hex + 2) {
                return false;
            }
            bytes[len] = (uint8_t) value;
            mask[len] = 'x';
            p += 2;
        }
        len++;
    }

    mask[len] = 0;
    *out_len = len;
    return len > 0;
}

static bool pattern_matches(const uint8_t* data, const uint8_t* bytes, const char* mask, size_t len) {
    for(size_t i = 0; i < len; i++) {
        if(mask[i] != '?' && data[i] != bytes[i]) {
            return false;
        }
    }
    return true;
}

static void* find_pattern(struct iboot_img* iboot_in, const char* text) {
    uint8_t bytes[128];
    char mask[129];
    size_t len = 0;

    if(!parse_pattern(text, bytes, mask, sizeof(bytes), &len)) {
        return NULL;
    }
    if(len > iboot_in->len) {
        return NULL;
    }

    const uint8_t* buf = (const uint8_t*) iboot_in->buf;
    for(size_t i = 0; i + len <= iboot_in->len; i++) {
        if(pattern_matches(buf + i, bytes, mask, len)) {
            return (void*) (buf + i);
        }
    }
    return NULL;
}

static void* find_previous_pattern(struct iboot_img* iboot_in, const void* start, size_t max_back, const char* text) {
    uint8_t bytes[128];
    char mask[129];
    size_t len = 0;

    if(!parse_pattern(text, bytes, mask, sizeof(bytes), &len)) {
        return NULL;
    }

    const uint8_t* buf = (const uint8_t*) iboot_in->buf;
    const uint8_t* pos = (const uint8_t*) start;
    if(pos < buf || pos > buf + iboot_in->len) {
        return NULL;
    }

    size_t available = (size_t) (pos - buf);
    if(available > max_back) {
        available = max_back;
    }

    for(size_t back = 0; back <= available; back++) {
        const uint8_t* candidate = pos - back;
        if((size_t) (candidate - buf) + len > iboot_in->len) {
            continue;
        }
        if(pattern_matches(candidate, bytes, mask, len)) {
            return (void*) candidate;
        }
    }
    return NULL;
}

static uint32_t pointer_to_va(struct iboot_img* iboot_in, const void* ptr) {
    if(!ptr) {
        return 0;
    }
    return (uint32_t) ((const uint8_t*) ptr - (const uint8_t*) iboot_in->buf) + get_iboot_base_address(iboot_in->buf);
}

static bool thumb_ldr_literal(struct iboot_img* iboot_in, const uint8_t* insn, uint32_t* literal_offset, uint8_t* rd) {
    const uint8_t* buf = (const uint8_t*) iboot_in->buf;
    size_t offset = (size_t) (insn - buf);
    if(offset + 2 > iboot_in->len) {
        return false;
    }

    uint16_t opcode = (uint16_t) insn[0] | ((uint16_t) insn[1] << 8);
    if((opcode & 0xF800) != 0x4800) {
        return false;
    }

    size_t pc = (offset + 4) & ~(size_t) 3;
    size_t literal = pc + ((opcode & 0xFF) * 4);
    if(literal + 4 > iboot_in->len) {
        return false;
    }

    *literal_offset = (uint32_t) literal;
    *rd = (uint8_t) ((opcode >> 8) & 7);
    return true;
}

static uint32_t find_hfs_context(struct iboot_img* iboot_in, void** hfs_init) {
    const char* name = "HFSInitPartition";
    const uint8_t* buf = (const uint8_t*) iboot_in->buf;
    uint8_t* str = (uint8_t*) memmem(iboot_in->buf, (int) iboot_in->len, name, (int) strlen(name));
    if(!str) {
        return 0;
    }

    uint32_t str_va = pointer_to_va(iboot_in, str);
    uint8_t* xref = (uint8_t*) memmem(iboot_in->buf, (int) iboot_in->len, &str_va, sizeof(str_va));
    if(!xref) {
        return 0;
    }

    uint8_t* function = (uint8_t*) find_previous_pattern(iboot_in, xref, 0x400, "f0 b5 03 af");
    if(!function) {
        return 0;
    }
    if(hfs_init) {
        *hfs_init = function;
    }

    for(size_t i = 0; i < 0x30; i += 2) {
        if(function + i + 2 > buf + iboot_in->len) {
            break;
        }

        uint32_t literal = 0;
        uint8_t rd = 0;
        if(thumb_ldr_literal(iboot_in, function + i, &literal, &rd) && rd == 4) {
            uint32_t value = *(uint32_t*) (buf + literal);
            uint32_t base = get_iboot_base_address(iboot_in->buf);
            if(value >= base && value < base + 0x01000000) {
                return value;
            }
        }
    }

    for(size_t i = 0; i < 0x30; i += 2) {
        if(function + i + 2 > buf + iboot_in->len) {
            break;
        }

        uint32_t literal = 0;
        uint8_t rd = 0;
        if(thumb_ldr_literal(iboot_in, function + i, &literal, &rd)) {
            uint32_t value = *(uint32_t*) (buf + literal);
            uint32_t base = get_iboot_base_address(iboot_in->buf);
            if(value >= base && value < base + 0x01000000) {
                return value;
            }
        }
    }

    return 0;
}

static void* find_platform_init(struct iboot_img* iboot_in, void* find_boot_images) {
    const uint8_t* buf = (const uint8_t*) iboot_in->buf;
    if(!find_boot_images) {
        return NULL;
    }

    size_t target = (size_t) ((const uint8_t*) find_boot_images - buf);
    uintptr_t target_addr = (uintptr_t) (buf + target) & ~(uintptr_t) 1;
    for(size_t i = 0; i + 4 <= iboot_in->len; i += 2) {
        uintptr_t resolved = (uintptr_t) resolve_bl32(buf + i) & ~(uintptr_t) 1;
        if(resolved != target_addr) {
            continue;
        }

        size_t start = i > 0x40 ? i - 0x40 : 0;
        for(size_t j = start; j < i; j += 2) {
            uintptr_t candidate_addr = (uintptr_t) resolve_bl32(buf + j) & ~(uintptr_t) 1;
            if(candidate_addr < (uintptr_t) buf || candidate_addr + 16 > (uintptr_t) (buf + iboot_in->len)) {
                continue;
            }
            const uint8_t* candidate = (const uint8_t*) candidate_addr;
            if(candidate[0] == 0x80 && candidate[1] == 0xB5 &&
               candidate[2] == 0x6F && candidate[3] == 0x46 &&
               candidate[12] == 0x00 && candidate[13] == 0x20 &&
               candidate[14] == 0x80 && candidate[15] == 0xBD) {
                return (void*) candidate;
            }
        }
    }
    return NULL;
}

static void print_entry(struct iboot_img* iboot_in, const char* name, void* ptr, int thumb, const char* note) {
    if(!ptr) {
        printf("  %-24s not found\n", name);
        return;
    }

    uint32_t va = pointer_to_va(iboot_in, ptr);
    printf("  %-24s 0x%08X", name, va);
    if(thumb) {
        printf("  thumb 0x%08X", va + 1);
    }
    if(note && note[0]) {
        printf("  %s", note);
    }
    printf("\n");
}

static void print_define(const char* name, uint32_t value, int thumb) {
    if(thumb) {
        printf("#define %-30s (0x%08X + 1)\n", name, value);
    } else {
        printf("#define %-30s (0x%08X)\n", name, value);
    }
}

int print_config_finder(struct iboot_img* iboot_in) {
    void* printf_fn = find_pattern(iboot_in, "83 b0 80 b5 6f 46 85 b0");
    void* memset_fn = find_pattern(iboot_in, "02 30 a0 e1 ff 10 01 e2 01 14 81 e1 01 28 81 e1");
    void* cache_fn = find_pattern(iboot_in, "00 40 2d e9 ?? ?? ?? ?? ?? ?? ?? ?? 00 40 bd e8 1e ff 2f e1");
    void* irq_fn = find_pattern(iboot_in, "00 00 0f e1 80 10 80 e3 01 f0 21 e1 80 00 00 e2 1e ff 2f e1");
    void* wrapper_fn = find_pattern(iboot_in, "00 68 d0 f8 1c 90 48 47");
    void* find_boot_images = find_pattern(iboot_in, "f0 b5 03 af ?? 48 00 24");
    void* image_load_type = find_pattern(iboot_in, "f0 b5 03 af 14 46 06 46 20 46 0d 46 ?? ?? ?? ?? 4f f0 ff 31 28 b1");
    void* prepare_and_jump = find_pattern(iboot_in, "f0 b5 03 af 14 46 0d 46 06 46 ?? ?? ?? ?? 30 46");
    void* fs_load_file = find_pattern(iboot_in, "f0 b5 03 af 88 b0 0d 46 00 21 14 46");
    void* image3_patch_match = find_pattern(iboot_in, "b8 b1 4f f0 ff 36 01 28 40 f0 c4 81");
    void* image_list_print = find_pattern(iboot_in, "f0 b5 03 af 2d e9 00 05 85 b0 16 48 44 68 84 42 23 d0");
    void* image3_patch = NULL;
    void* hfs_init = NULL;

    if(image3_patch_match) {
        image3_patch = (uint8_t*) image3_patch_match - 4;
    }

    uint32_t hfs_context = find_hfs_context(iboot_in, &hfs_init);
    void* platform_init = find_platform_init(iboot_in, find_boot_images);

    printf("\n");
    printf("Base address: 0x%08X\n", get_iboot_base_address(iboot_in->buf));
    printf("iBoot version: %u\n", iboot_in->VERS);
    printf("Image size: %zu bytes\n", iboot_in->len);

    printf("\n[Functions]\n");
    print_entry(iboot_in, "PRINTF", printf_fn, 1, "pattern");
    print_entry(iboot_in, "MEMSET", memset_fn, 0, "pattern");
    print_entry(iboot_in, "ARM_CLEAN_CACHES", cache_fn, 0, "pattern");
    print_entry(iboot_in, "DISABLE_INTERRUPTS", irq_fn, 0, "pattern");
    print_entry(iboot_in, "PLATFORM_INIT", platform_init, 1, "caller of FIND_BOOT_IMAGES");
    print_entry(iboot_in, "FIND_BOOT_IMAGES", find_boot_images, 1, "pattern");
    print_entry(iboot_in, "IMAGE_LOAD_TYPE", image_load_type, 1, "pattern");
    print_entry(iboot_in, "PREPARE_AND_JUMP", prepare_and_jump, 1, "pattern");
    print_entry(iboot_in, "FS_LOAD_FILE", fs_load_file, 1, "pattern");

    printf("\n[HFS]\n");
    print_entry(iboot_in, "HFSInitPartition", hfs_init, 1, "string xref");
    if(hfs_context) {
        printf("  %-24s 0x%08X  ldr literal in HFSInitPartition\n", "STAGE1_HFS_CONTEXT", hfs_context);
    } else {
        printf("  %-24s not found\n", "STAGE1_HFS_CONTEXT");
    }
    print_entry(iboot_in, "STAGE1_HFS_WRAPPER", wrapper_fn, 1, "pattern");

    printf("\n[HFS fields]\n");
    if(hfs_context) {
        printf("  %-24s 0x%08X  context + 0x31C\n", "catalog buffer", hfs_context + 0x31C);
        printf("  %-24s 0x%08X  context + 0x41C\n", "extents buffer", hfs_context + 0x41C);
        printf("  %-24s 0x%08X  context + 0x440\n", "fake base", hfs_context + 0x440);
        printf("  %-24s 0x%08X  context + 0x520\n", "heap metadata", hfs_context + 0x520);
        printf("  %-24s 0x%08X  context + 0x550\n", "allocator head", hfs_context + 0x550);
    } else {
        printf("  not available without STAGE1_HFS_CONTEXT\n");
    }

    printf("\n[Patch sites]\n");
    print_entry(iboot_in, "IMAGE3_PATCH", image3_patch, 0, "pattern, match - 4");
    print_entry(iboot_in, "IMAGE_LIST_PRINT", image_list_print, 0, "pattern");

    printf("\n[Runtime-only / not statically resolvable]\n");
    printf("  STAGE1_STACK\n");
    printf("  STAGE1_BASE\n");
    printf("  TARGET_BK\n");
    printf("  HEAP_CHUNKS\n");

    printf("\n/* config.h candidates; verify before use */\n");
    if(hfs_context) {
        print_define("STAGE1_HFS_CONTEXT", hfs_context, 0);
    } else {
        printf("/* STAGE1_HFS_CONTEXT not found */\n");
    }
    if(wrapper_fn) {
        print_define("STAGE1_HFS_WRAPPER", pointer_to_va(iboot_in, wrapper_fn), 1);
    } else {
        printf("/* STAGE1_HFS_WRAPPER not found */\n");
    }
    if(printf_fn) {
        print_define("PRINTF", pointer_to_va(iboot_in, printf_fn), 1);
    } else {
        printf("/* PRINTF not found */\n");
    }
    if(memset_fn) {
        print_define("MEMSET", pointer_to_va(iboot_in, memset_fn), 0);
    } else {
        printf("/* MEMSET not found */\n");
    }
    if(cache_fn) {
        print_define("ARM_CLEAN_CACHES", pointer_to_va(iboot_in, cache_fn), 0);
    } else {
        printf("/* ARM_CLEAN_CACHES not found */\n");
    }
    if(irq_fn) {
        print_define("DISABLE_INTERRUPTS", pointer_to_va(iboot_in, irq_fn), 0);
    } else {
        printf("/* DISABLE_INTERRUPTS not found */\n");
    }
    if(platform_init) {
        print_define("PLATFORM_INIT", pointer_to_va(iboot_in, platform_init), 1);
    } else {
        printf("/* PLATFORM_INIT not found */\n");
    }
    if(find_boot_images) {
        print_define("FIND_BOOT_IMAGES", pointer_to_va(iboot_in, find_boot_images), 1);
    } else {
        printf("/* FIND_BOOT_IMAGES not found */\n");
    }
    if(image_load_type) {
        print_define("IMAGE_LOAD_TYPE", pointer_to_va(iboot_in, image_load_type), 1);
    } else {
        printf("/* IMAGE_LOAD_TYPE not found */\n");
    }
    if(prepare_and_jump) {
        print_define("PREPARE_AND_JUMP", pointer_to_va(iboot_in, prepare_and_jump), 1);
    } else {
        printf("/* PREPARE_AND_JUMP not found */\n");
    }
    if(fs_load_file) {
        print_define("FS_LOAD_FILE", pointer_to_va(iboot_in, fs_load_file), 1);
    } else {
        printf("/* FS_LOAD_FILE not found */\n");
    }
    if(hfs_context) {
        print_define("HEAP_METADATA", hfs_context + 0x520, 0);
    } else {
        printf("/* HEAP_METADATA not found */\n");
    }
    printf("#define %-30s 0x5\n", "HEAP_BLOCKSIZE_SHIFT");
    printf("/* HEAP_CHUNKS: runtime heap, not statically resolvable */\n");
    if(image3_patch) {
        print_define("IMAGE3_PATCH", pointer_to_va(iboot_in, image3_patch), 0);
    } else {
        printf("/* IMAGE3_PATCH not found */\n");
    }
    if(image_list_print) {
        print_define("IMAGE_LIST_PRINT", pointer_to_va(iboot_in, image_list_print), 0);
    } else {
        printf("/* IMAGE_LIST_PRINT not found */\n");
    }
    printf("#define %-30s (0x69626F62)\n", "IMAGE3_TYPE_IBOB");
    printf("#define %-30s (0x80000000)\n", "IBOB_LOAD_ADDR");
    printf("#define %-30s (0x00100000)\n", "IBOB_MAX_SIZE");
    printf("#define %-30s (2)\n", "BOOT_IBOOT");

    printf("\n/* env candidates */\n");
    if(hfs_context) {
        printf("TARGET_EXTENTS_BUF=0x%08X\n", hfs_context + 0x41C);
        printf("TARGET_FAKE_BASE=0x%08X\n", hfs_context + 0x440);
        printf("TARGET_METADATA=0x%08X\n", hfs_context + 0x520);
    } else {
        printf("TARGET_EXTENTS_BUF=unknown\n");
        printf("TARGET_FAKE_BASE=unknown\n");
        printf("TARGET_METADATA=unknown\n");
    }
    printf("TARGET_STAGE1_BASE=unknown\n");
    printf("TARGET_BK=unknown\n");

    return 0;
}
