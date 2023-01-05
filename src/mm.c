#include "page.h"
#include "mm.h"
#include "assert.h"
#include <sbi/sbi_string.h>

extern char _runtime_start;
extern char _runtime_end;

pte* __ept_walk_internal(uintptr_t addr, int create, uintptr_t rootPageTable, uintptr_t* epmFreeList);
pte* __ept_walk_create(uintptr_t addr, uintptr_t rootPageTable, uintptr_t* epmFreeList);
pte* __ept_continue_walk_create(uintptr_t addr, pte* pte, uintptr_t rootPageTable, uintptr_t* epmFreeList);
pte* __ept_walk(uintptr_t addr, uintptr_t rootPageTable, uintptr_t* epmFreeList);
inline pte ptd_create(uintptr_t ppn);
inline pte pte_create(uintptr_t ppn,int type);
uintptr_t readMem(uintptr_t src, size_t size);
void writeMem(uintptr_t src, uintptr_t dst, size_t size);

bool allocPage(uintptr_t va, uintptr_t src, unsigned int mode, uintptr_t rootPageTable, uintptr_t* epmFreeList);

bool mapEapp(uintptr_t epmStartAddr, size_t epmSize, uintptr_t eappStartAddr, size_t eappSize, uintptr_t rootPageTable, uintptr_t* epmFreeList);
bool mapRuntime(uintptr_t epmStartAddr, size_t epmSize, uintptr_t rootPageTable, uintptr_t* epmFreeList);

inline pte
pte_create(uintptr_t ppn, int type) {
  return __pte((ppn << PTE_PPN_SHIFT) | PTE_V | type);
}

inline pte
ptd_create(uintptr_t ppn) {
  return pte_create(ppn, PTE_V);
}

uintptr_t
pte_ppn(pte pte) {
  return pte_val(pte) >> PTE_PPN_SHIFT;
}

uintptr_t
ppn(uintptr_t addr) {
  return __pa(addr) >> RISCV_PGSHIFT;
}

size_t
pt_idx(uintptr_t addr, int level) {
  size_t idx = addr >> (RISCV_PGLEVEL_BITS * level + RISCV_PGSHIFT);
  return idx & ((1 << RISCV_PGLEVEL_BITS) - 1);
}

pte*
__ept_walk_internal(uintptr_t addr, int create, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  pte* t = (pte*)rootPageTable;

  int i;
  for (i = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS - 1; i > 0; i--) {
    size_t idx = pt_idx(addr, i);
    if (!(pte_val(t[idx]) & PTE_V)) {
      sbi_printf("Need to create PT page for: %lx \n", (unsigned long)addr);
      return create ? __ept_continue_walk_create(addr, &t[idx], rootPageTable, epmFreeList) : 0;
    }

    t = (pte*)(readMem(
        (uintptr_t)(pte_ppn(t[idx]) << RISCV_PGSHIFT),
        PAGE_SIZE));
  }
  return &t[pt_idx(addr, 0)];
}

pte*
__ept_walk_create(uintptr_t addr, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  return __ept_walk_internal(addr, 1,rootPageTable,epmFreeList);
}

pte*
__ept_continue_walk_create(uintptr_t addr, pte* pte, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  uintptr_t free_ppn = ppn(*epmFreeList);
  *pte              = ptd_create(free_ppn);
  *epmFreeList = *epmFreeList +  PAGE_SIZE;
  return __ept_walk_create(addr, rootPageTable, epmFreeList);
}

pte*
__ept_walk(uintptr_t addr, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  return __ept_walk_internal(addr, 0, rootPageTable, epmFreeList);
}

uintptr_t
epm_va_to_pa(uintptr_t addr, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  pte* pte = __ept_walk(addr, rootPageTable, epmFreeList);
  if (pte)
    return pte_ppn(*pte) << RISCV_PGSHIFT;
  else
    return 0;
}

uintptr_t readMem(uintptr_t src, size_t size){
   return src;
}
void
writeMem(uintptr_t src, uintptr_t dst, size_t size) {
  sbi_memcpy((void*)dst, (void*)src, size);
}

bool
allocPage(uintptr_t va, uintptr_t src, unsigned int mode, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  uintptr_t page_addr;
  uintptr_t* pFreeList = epmFreeList;

  pte* pte = __ept_walk_create(va, rootPageTable, epmFreeList);

  /* if the page has been already allocated, return the page */
  if (pte_val(*pte) & PTE_V) {
    return true;
  }

  /* otherwise, allocate one from EPM freelist */
  page_addr = *pFreeList >> PAGE_BITS;
  *pFreeList += PAGE_SIZE;

  switch (mode) {
    case USER_NOEXEC: {
      *pte =
          pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_U | PTE_V);
      break;
    }
    case RT_NOEXEC: {
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_V);
      break;
    }
    case RT_FULL: {
      *pte =
          pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_V);
      writeMem(src, (uintptr_t)page_addr << PAGE_BITS, PAGE_SIZE);

      break;
    }
    case USER_FULL: {
      *pte = pte_create(
          page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_U | PTE_V);

      writeMem(src, (uintptr_t)page_addr << PAGE_BITS, PAGE_SIZE);
      break;
    }
    case UTM_FULL: {
      sm_assert(!src);
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_V);
      break;
    }
    default: {

      return false;
    }
  }
  return true;
}

bool
mapPage(uintptr_t va, uintptr_t start, unsigned int mode, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  uintptr_t page_addr;

  pte* pte = __ept_walk_create(va, rootPageTable, epmFreeList);

  /* if the page has been already allocated, return the page */
  if (pte_val(*pte) & PTE_V) {
    //return true;
  }

  page_addr = start >> PAGE_BITS;

  switch (mode) {
    case USER_NOEXEC: {
      *pte =
          pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_U | PTE_V);
      break;
    }
    case RT_NOEXEC: {
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_V);
      break;
    }
    case RT_FULL: {
      *pte =
          pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_V);
      break;
    }
    case USER_FULL: {
      *pte = pte_create(
          page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_U | PTE_V);
      break;
    }
    case UTM_FULL: {
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_V);
      break;
    }
    default: {

      return false;
    }
  }
  return true;
}
// eppSize includes not only bin file, but also stack size.
unsigned long
allocate_epm(uintptr_t epmStartAddr, size_t epmSize, uintptr_t eappStartAddr, size_t eappSize){
  sm_assert(epmStartAddr <= eappStartAddr);
  sm_assert(eappStartAddr + eappSize <= epmStartAddr + epmSize);

  pte old_root_page_table[BIT(RISCV_PT_INDEX_BITS)];
  sbi_memcpy(old_root_page_table,(const void*) epmStartAddr, PAGE_SIZE);
  sbi_memset((void*)epmStartAddr ,0, eappStartAddr - epmStartAddr);
  sbi_memset((void*)eappStartAddr + eappSize, 0, epmStartAddr + epmSize - eappStartAddr - eappSize);

  uintptr_t epmFreeList = epmStartAddr;
  uintptr_t rootPageTable = epmFreeList;
  epmFreeList += PAGE_SIZE;
  if(!mapRuntime(epmStartAddr, epmSize,rootPageTable, &epmFreeList)){
     return SBI_ERR_SM_ENCLAVE_RT_PT_WRONG;
  }

  if(!mapEapp(epmStartAddr, epmSize, eappStartAddr, 2048, rootPageTable, &epmFreeList)){
     return SBI_ERR_SM_ENCLAVE_EAPP_PT_WRONG;
  }

  int i;
  pte* root_page_table =  (pte*) rootPageTable;
  for (i = 0; i < BIT(RISCV_PT_INDEX_BITS); i++) {
    if (pte_val(old_root_page_table[i]) & PTE_V &&
        !(pte_val(root_page_table[i]) & PTE_V)) {
      root_page_table[i] = old_root_page_table[i];
    }
  }

  return 0;
}

size_t
epmAllocVspace(uintptr_t addr, size_t num_pages, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  size_t count;

  for (count = 0; count < num_pages; count++, addr += PAGE_SIZE) {
    pte* pte = __ept_walk_create(addr,rootPageTable, epmFreeList);
    if (!pte) break;
  }
  return count;
}

bool mapRuntime(uintptr_t epmStartAddr, size_t epmSize, uintptr_t rootPageTable, uintptr_t* epmFreeList){
  size_t runtime_size = &_runtime_end - &_runtime_start;
  //size_t runtime_size = 0x18000;
  sm_assert(*epmFreeList >= epmStartAddr);
  sm_assert(*epmFreeList < epmStartAddr + epmSize);
  sm_assert(runtime_size > 0);
  sm_assert(*epmFreeList + runtime_size < epmStartAddr + epmSize );

  size_t num_pages = ROUND_UP(runtime_size, PAGE_BITS) / PAGE_SIZE;
  uintptr_t src = (uintptr_t) &_runtime_start;

  if (epmAllocVspace(RUNTIME_ENTRY_VA, num_pages,rootPageTable, epmFreeList) != num_pages) {
    sbi_printf("Failed to allocate vspace for runtime in SM\n");
    return false;
  }

  uintptr_t va = ROUND_DOWN(RUNTIME_ENTRY_VA, PAGE_BITS);;

  while (va + PAGE_SIZE <= RUNTIME_ENTRY_VA + num_pages * PAGE_SIZE ) {
      sbi_printf("rt begin to map va: %lx, epmFreeList： %lx\n", (unsigned long)va, (unsigned long)*epmFreeList);
      if (!allocPage(va, (uintptr_t)src, RT_FULL, rootPageTable, epmFreeList)){
        sbi_printf("Error happen va: %lx, epmFreeList： %lx\n", (unsigned long)va, (unsigned long)*epmFreeList);
        return false;
      }

      src += PAGE_SIZE;
      va += PAGE_SIZE;
  }
  return true;
}

bool mapEapp(uintptr_t epmStartAddr, size_t epmSize, uintptr_t eappStartAddr, size_t eappSize, uintptr_t rootPageTable, uintptr_t* epmFreeList){

  sm_assert(eappStartAddr >= epmStartAddr);
  sm_assert(eappStartAddr + eappSize <= epmStartAddr + epmSize);
  sm_assert(*epmFreeList >= epmStartAddr && epmStartAddr < epmStartAddr + epmSize);
  sm_assert(*epmFreeList + eappSize <= epmStartAddr + epmSize);
  uintptr_t page_va_start = ROUND_DOWN(EAPP_ENTRY_VA, PAGE_BITS);
  sbi_printf("Map Eapp epm start: %x, empSize: %x, eappStart: %x, eappSize: %x, epmFreeList: %x \n",
             (unsigned int)epmStartAddr, (unsigned int)epmSize, (unsigned int)eappStartAddr,(unsigned int)eappSize, (unsigned int)*epmFreeList);
  size_t num_pages = ROUND_UP(eappSize, PAGE_BITS) / PAGE_SIZE;
  if (epmAllocVspace(page_va_start, num_pages, rootPageTable, epmFreeList) != num_pages) {
    sbi_printf("Failed to allocate vspace for eapp in SM\n");
    return false;
  }

  *epmFreeList = *epmFreeList + PAGE_SIZE*num_pages;

  uintptr_t va = page_va_start;
  uintptr_t src = eappStartAddr;

  while (va + PAGE_SIZE <= page_va_start + num_pages * PAGE_SIZE) {

    if (!mapPage(va, src, USER_FULL, rootPageTable, epmFreeList)){
        sbi_printf("mapPage error va: %x, epmFreeList： %x\n", (unsigned int)va, (unsigned int)*epmFreeList);
        return false;
    }
    src += PAGE_SIZE;
    va += PAGE_SIZE;
  }
  return true;
}
