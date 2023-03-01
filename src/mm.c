#include "page.h"
#include "mm.h"
#include "assert.h"
#include <sbi/sbi_string.h>
#include "common.h"
#include "elf/elf.h"

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

bool allocPage(uintptr_t va, uintptr_t src, unsigned int mode, uintptr_t rootPageTable, uintptr_t* epmFreeList,uintptr_t* utmFreeList);

bool mapEapp(uintptr_t epmStartAddr, size_t epmSize, uintptr_t eappStartAddr, size_t eappSize, uintptr_t rootPageTable, uintptr_t* epmFreeList);
bool mapRuntime(uintptr_t epmStartAddr, size_t epmSize, uintptr_t rootPageTable, uintptr_t* epmFreeList);

bool initializeStack(uintptr_t start, size_t size, bool is_rt,uintptr_t rootPageTable, uintptr_t* epmFreeList);
bool allocateUntrusted(uintptr_t va_utm_start, size_t utm_size, uintptr_t rootPageTable, uintptr_t* epmFreeList, uintptr_t* utmFreeList);
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
      debug("Need to create PT page for: %lx \n", (unsigned long)addr);
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
allocPage(uintptr_t va, uintptr_t src, unsigned int mode, uintptr_t rootPageTable, uintptr_t* epmFreeList, uintptr_t* utmFreeList) {
  uintptr_t page_addr;

  uintptr_t* pFreeList = (mode == UTM_FULL ? utmFreeList : epmFreeList);
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

size_t
epmAllocVspace(uintptr_t addr, size_t num_pages, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  size_t count;

  for (count = 0; count < num_pages; count++, addr += PAGE_SIZE) {
    pte* pte = __ept_walk_create(addr,rootPageTable, epmFreeList);
    if (!pte) break;
  }
  return count;
}

// eppSize includes not only bin file, but also stack size.
unsigned long
allocate_epm(uintptr_t epmStartAddr, size_t epmSize, uintptr_t eappStartAddr, size_t eappSize, uintptr_t utm_start, size_t utm_size, uintptr_t va_utm_start){
  if(!(epmStartAddr <= eappStartAddr)) return SBI_ERR_SM_ENCLAVE_PARA_WRONG;
  if(!(eappStartAddr + eappSize <= epmStartAddr + epmSize)) return SBI_ERR_SM_ENCLAVE_PARA_WRONG;

  debug("empStart: %lx, epmSize: %lx\n", (unsigned long)epmStartAddr, (unsigned long)epmSize);
  debug("eappStart: %lx, eappSize: %lx\n", (unsigned long)eappStartAddr, (unsigned long)eappSize);
  debug("utm_start: %lx, utm_size: %x, va_utm_size: %lx\n", (unsigned long)utm_start, (unsigned int)utm_size,(unsigned long)va_utm_start );

  pte old_root_page_table[BIT(RISCV_PT_INDEX_BITS)];
  sbi_memcpy(old_root_page_table,(const void*) epmStartAddr, PAGE_SIZE);
  sbi_memset((void*)epmStartAddr ,0, eappStartAddr - epmStartAddr);
  sbi_memset((void*)eappStartAddr + eappSize, 0, epmStartAddr + epmSize - eappStartAddr - eappSize);

  uintptr_t epmFreeList = epmStartAddr;
  uintptr_t rootPageTable = epmFreeList;
  epmFreeList += PAGE_SIZE;
  if(!mapRuntime(epmStartAddr, epmSize,rootPageTable, &epmFreeList)){
     return SBI_ERR_SM_ENCLAVE_RT_MAP_WRONG;
  }

  if(!mapEapp(epmStartAddr, epmSize, eappStartAddr, eappSize, rootPageTable, &epmFreeList)){
     return SBI_ERR_SM_ENCLAVE_EAPP_MAP_WRONG;
  }


#ifndef USE_FREEMEM
  if (!initializeStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0,rootPageTable, &epmFreeList)) {
     return SBI_ERR_SM_ENCLAVE_EAPP_INIT_STACK_WRONG;
  }
#endif

  if(!allocateUntrusted(va_utm_start, utm_size, rootPageTable,&epmFreeList, &utm_start)){
    return SBI_ERR_SM_ENCLAVE_UNTRUST_WRONG;
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

bool mapElf(elf_t* elf, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  uintptr_t va;

  uintptr_t minVaddr;
  uintptr_t maxVaddr;
    /* get bound vaddrs */
  elf_getMemoryBounds(elf, VIRTUAL, &minVaddr, &maxVaddr);

  if (!IS_ALIGNED(minVaddr, PAGE_SIZE)) {
    return false;
  }

  maxVaddr = ROUND_UP(maxVaddr, PAGE_BITS);
  size_t totalMemorySize = maxVaddr - minVaddr;
  size_t num_pages =
    ROUND_DOWN(totalMemorySize, PAGE_BITS) / PAGE_SIZE;
  va = minVaddr;

  if(epmAllocVspace(va, num_pages, rootPageTable, epmFreeList) != num_pages){
    sbi_printf("failed to allocate vspace\n");
    return false;
  }
  return true;
}

bool loadElf(elf_t* elf, unsigned int mode, uintptr_t rootPageTable, uintptr_t* epmFreeList) {
  static char nullpage[PAGE_SIZE] = {
      0,
  };

  for (unsigned int i = 0; i < elf_getNumProgramHeaders(elf); i++) {
    if (elf_getProgramHeaderType(elf, i) != PT_LOAD) {
      continue;
    }

    uintptr_t start      = elf_getProgramHeaderVaddr(elf, i);
    uintptr_t file_end   = start + elf_getProgramHeaderFileSize(elf,i);
    uintptr_t memory_end = start + elf_getProgramHeaderMemorySize(elf,i);
    char* src            = (char*)(elf_getProgramSegment(elf,i));
    uintptr_t va         = start;

    /* FIXME: This is a temporary fix for loading iozone binary
     * which has a page-misaligned program header. */
    if (!IS_ALIGNED(va, PAGE_SIZE)) {
      size_t offset = va - PAGE_DOWN(va);
      size_t length = PAGE_UP(va) - va;
      char page[PAGE_SIZE];
      sbi_memset(page, 0, PAGE_SIZE);
      sbi_memcpy(page + offset, (const void*)src, length);
      //if (!pMemory->allocPage(PAGE_DOWN(va), (uintptr_t)page, mode))
      if (!allocPage(PAGE_DOWN(va), (uintptr_t)page, mode, rootPageTable, epmFreeList, 0)){
         sbi_printf("Error happen va: %lx, epmFreeList： %lx\n", (unsigned long)va, (unsigned long)*epmFreeList);
         return false;
      }

      va += length;
      src += length;
    }

    /* first load all pages that do not include .bss segment */
    while (va + PAGE_SIZE <= file_end) {
     //if (!pMemory->allocPage(va, (uintptr_t)src, mode))
      if (!allocPage(va, (uintptr_t)src, mode, rootPageTable, epmFreeList, 0)){
         sbi_printf("Error happen va: %lx, epmFreeList： %lx\n", (unsigned long)va, (unsigned long)*epmFreeList);
         return false;
     }

      src += PAGE_SIZE;
      va += PAGE_SIZE;
    }

    /* next, load the page that has both initialized and uninitialized segments
     */
    if (va < file_end) {
      char page[PAGE_SIZE];
      sbi_memset(page, 0, PAGE_SIZE);
      sbi_memcpy(page, (const void*)src, (size_t)(file_end - va));

      //if (!pMemory->allocPage(va, (uintptr_t)page, mode))
      if (!allocPage(va, (uintptr_t)page, mode, rootPageTable, epmFreeList, 0)){
        sbi_printf("Error happen va: %lx, epmFreeList： %lx\n", (unsigned long)va, (unsigned long)*epmFreeList);
        return false;
      }

      va += PAGE_SIZE;
    }

    /* finally, load the remaining .bss segments */
    while (va < memory_end) {
      //if (!pMemory->allocPage(va, (uintptr_t)nullpage, mode))
      if (!allocPage(va, (uintptr_t)nullpage, mode, rootPageTable, epmFreeList, 0)){
        sbi_printf("Error happen va: %lx, epmFreeList： %lx\n", (unsigned long)va, (unsigned long)*epmFreeList);
        return false;
      }
      va += PAGE_SIZE;
    }
  }

  return true;
}


// eppSize includes not only bin file, but also stack size.
unsigned long
allocateEpm(struct enclave* encl){

  uintptr_t epm_start, epm_size, utm_start, utm_size;

  int idx = get_enclave_region_index(encl->eid, REGION_EPM);
  epm_start = pmp_region_get_addr(encl->regions[idx].pmp_rid);
  epm_size = pmp_region_get_size(encl->regions[idx].pmp_rid);

  idx = get_enclave_region_index(encl->eid, REGION_UTM);
  utm_start = pmp_region_get_addr(encl->regions[idx].pmp_rid);
  utm_size = pmp_region_get_size(encl->regions[idx].pmp_rid);

  sbi_memset((void*)epm_start ,0, epm_size);

  elf_t elfEapp, elfRuntime;

  uintptr_t epmFreeList = epm_start;
  uintptr_t rootPageTable = epmFreeList;
  epmFreeList += PAGE_SIZE;

  uintptr_t elfRuntimePtr = (uintptr_t) &_runtime_start;
  size_t elfRuntimeSize = &_runtime_end - &_runtime_start;
  if (elf_newFile((void*)elfRuntimePtr, elfRuntimeSize, &elfRuntime)) {
    return SBI_ERR_SM_ENCLAVE_INPUT_RT_ELF_WRONG;
  }

  encl->params.runtime_entry = elf_getEntryPoint(&elfRuntime);

  if(!mapElf(&elfRuntime,rootPageTable,&epmFreeList)){
     return SBI_ERR_SM_ENCLAVE_RT_MAP_WRONG;
  }

  encl->pa_params.runtime_base = epmFreeList;
  if(!loadElf(&elfRuntime, RT_FULL,rootPageTable,&epmFreeList)){
     return SBI_ERR_SM_ENCLAVE_RT_LOAD_WRONG;
  }

  uintptr_t elfEappPtr = utm_start + sizeof(int);
  int elfEappSize = *(int*)utm_start;
  if (elf_newFile((void*)elfEappPtr, elfEappSize, &elfEapp)) {
    return SBI_ERR_SM_ENCLAVE_INPUT_EAPP_ELF_WRONG;
  }

  encl->params.user_entry = elf_getEntryPoint(&elfEapp);

  if(!mapElf(&elfEapp,rootPageTable,&epmFreeList)){
     return SBI_ERR_SM_ENCLAVE_EAPP_MAP_WRONG;
  }

  encl->pa_params.user_base = epmFreeList;
  if(!loadElf(&elfEapp, USER_FULL,rootPageTable,&epmFreeList)){
     return SBI_ERR_SM_ENCLAVE_EAPP_LOAD_WRONG;
  }

#ifndef USE_FREEMEM
  if (!initializeStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0,rootPageTable, &epmFreeList)) {
     return SBI_ERR_SM_ENCLAVE_EAPP_INIT_STACK_WRONG;
  }
#endif

  uintptr_t va_utm_start = encl->params.untrusted_ptr;
  if(!allocateUntrusted(va_utm_start, utm_size, rootPageTable,&epmFreeList, &utm_start)){
    return SBI_ERR_SM_ENCLAVE_UNTRUST_WRONG;
  }

  encl->pa_params.free_base = epmFreeList;

  return 0;
}

bool mapRuntime(uintptr_t epmStartAddr, size_t epmSize, uintptr_t rootPageTable, uintptr_t* epmFreeList){
  size_t runtime_size = &_runtime_end - &_runtime_start;
  //size_t runtime_size = 0x18000;
  if(!(*epmFreeList >= epmStartAddr)) return false;
  if(!(*epmFreeList < epmStartAddr + epmSize)) return false;
  if(!(runtime_size > 0)) return false;
  if(!(*epmFreeList + runtime_size < epmStartAddr + epmSize)) return false;

  size_t num_pages = ROUND_UP(runtime_size, PAGE_BITS) / PAGE_SIZE;
  uintptr_t src = (uintptr_t) &_runtime_start;

  if (epmAllocVspace(RUNTIME_ENTRY_VA, num_pages,rootPageTable, epmFreeList) != num_pages) {
    sbi_printf("Failed to allocate vspace for runtime in SM\n");
    return false;
  }

  uintptr_t va = ROUND_DOWN(RUNTIME_ENTRY_VA, PAGE_BITS);;

  while (va + PAGE_SIZE <= RUNTIME_ENTRY_VA + num_pages * PAGE_SIZE ) {
      debug("rt begin to map va: %lx, epmFreeList： %lx\n", (unsigned long)va, (unsigned long)*epmFreeList);
      if (!allocPage(va, (uintptr_t)src, RT_FULL, rootPageTable, epmFreeList, 0)){
        sbi_printf("Error happen va: %lx, epmFreeList： %lx\n", (unsigned long)va, (unsigned long)*epmFreeList);
        return false;
      }

      src += PAGE_SIZE;
      va += PAGE_SIZE;
  }
  return true;
}

bool mapEapp(uintptr_t epmStartAddr, size_t epmSize, uintptr_t eappStartAddr, size_t eappSize, uintptr_t rootPageTable, uintptr_t* epmFreeList){

  if(!(eappStartAddr >= epmStartAddr)) return false;
  if(!(eappStartAddr + eappSize <= epmStartAddr + epmSize)) return false;
  if(!(*epmFreeList >= epmStartAddr && epmStartAddr < epmStartAddr + epmSize)) return false;
  if(!(*epmFreeList + eappSize <= epmStartAddr + epmSize)) return false;
  uintptr_t page_va_start = ROUND_DOWN(EAPP_ENTRY_VA, PAGE_BITS);
  debug("Map Eapp epm start: %x, empSize: %x, eappStart: %x, eappSize: %x, epmFreeList: %x \n",
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

bool
initializeStack(uintptr_t start, size_t size, bool is_rt,uintptr_t rootPageTable, uintptr_t* epmFreeList) {

  static char nullpage[PAGE_SIZE] = {
      0,
  };
  uintptr_t high_addr    = ROUND_UP(start, PAGE_BITS);
  uintptr_t va_start_stk = ROUND_DOWN((high_addr - size), PAGE_BITS);
  int stk_pages          = (high_addr - va_start_stk) / PAGE_SIZE;

  for (int i = 0; i < stk_pages; i++) {
    if (!allocPage(
            va_start_stk, (uintptr_t)nullpage,
            (is_rt ? RT_NOEXEC : USER_NOEXEC),
            rootPageTable, epmFreeList,0))
      return false;

    va_start_stk += PAGE_SIZE;
  }

  return true;
}

bool
allocateUntrusted(uintptr_t va_utm_start, size_t utm_size, uintptr_t rootPageTable, uintptr_t* epmFreeList, uintptr_t* utmFreeList) {
  uintptr_t va_start = ROUND_DOWN(va_utm_start, PAGE_BITS);
  uintptr_t va_end =   ROUND_UP(va_utm_start + utm_size, PAGE_BITS);

  while (va_start < va_end) {
    if (!allocPage(va_start, 0, UTM_FULL, rootPageTable,epmFreeList, utmFreeList)) {
      return false;
    }
    va_start += PAGE_SIZE;
  }
  return true;
}