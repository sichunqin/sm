#ifndef _MM_H_

#include "sm.h"

typedef struct {
  uintptr_t pte;
} pte;

#define pte_val(x) ((x).pte)

#define __pa(x) ((uintptr_t)(x))

#define __pte(x) ((pte){(x)})

#define PTE_PPN_SHIFT 10

#if __riscv_xlen == 32
#define VA_BITS 32
#define RISCV_PGLEVEL_BITS 10
#else  // __riscv_xlen == 64 or x86 test
#define VA_BITS 39
#define RISCV_PGLEVEL_BITS 9
#endif

#if __riscv_xlen == 64
#define RISCV_PGLEVEL_MASK 0x1ff
#define RISCV_PGTABLE_HIGHEST_BIT 0x100
#else
#define RISCV_PGLEVEL_MASK 0x3ff
#define RISCV_PGTABLE_HIGHEST_BIT 0x300
#endif

#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4

#define PAGE_BITS 12

#define ROUND_UP(n, b) (((((n)-1ul) >> (b)) + 1ul) << (b))
#define ROUND_DOWN(n, b) (n & ~((2 << (b - 1)) - 1))
#define PAGE_DOWN(n) ROUND_DOWN(n, PAGE_BITS)
#define PAGE_UP(n) ROUND_UP(n, PAGE_BITS)

#define RUNTIME_ENTRY_VA 0xffffffffc0000000
#define EAPP_ENTRY_VA    0x00000000000100b0
#define DEFAULT_STACK_SIZE 1024 * 16  // 16k
#define DEFAULT_STACK_START 0x0000000040000000

#define BIT(n) (1ul << (n))
#if __riscv_xlen == 64
#define RISCV_PT_INDEX_BITS 9
#define RISCV_PT_LEVELS 3
#elif __riscv_xlen == 32
#define RISCV_PT_INDEX_BITS 10
#define RISCV_PT_LEVELS 2
#endif

unsigned long allocate_epm(uintptr_t epmStartAdd, size_t epmSize, uintptr_t eappStartAddr, size_t eappSize, uintptr_t utm_start, size_t utm_size,uintptr_t va_utm_start);
#endif